#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <regex.h>
#include <string.h> // strlen , memchr

#define FIND 150

static uint32_t NF;     // DROP ACCEPT
static FILE *fp;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}


int jfopen(u_char *data_buf)
{

    u_char j_read_buff[200];
    int jmemcmp=0;
    int cmp=0;
    if(fp != NULL)
    {
        char *pStr=NULL;
        while(!feof(fp))
        {
            pStr = fgets((char *)j_read_buff,sizeof(j_read_buff),fp);
            //printf("TEST:: %s \n", pStr);
            jmemcmp = memcmp(pStr,data_buf,strlen((char*)pStr));
            if(!jmemcmp)
                printf("TEST True \n");
                cmp = FIND;
                break;
        }
        free(pStr);
    }
    if(cmp == FIND) return FIND;
    else return 0;
}


void check(unsigned char* buf)
{


    printf("\n");
    struct iphdr * ip_header =(struct iphdr *)buf;
    struct tcphdr * tcp_header = (struct tcphdr *) (buf + (ip_header->ihl<<2) );
    u_char * http = (u_char *)tcp_header + (tcp_header->th_off<<2); // next data 32



    regex_t state;
    //char *string ="Host: sungjun.yoon";
    const char *pattern= "Host: ([A-Za-z\\.0-9]+)";
    int rc;
    size_t nmatch =2;
    regmatch_t pmatch[1];
    char jbuffer[100];
    printf("\n");
    if((rc = regcomp(&state,pattern,REG_EXTENDED)) != 0){
        printf("regcomp error!! '%s' \n",jbuffer);
        exit(EXIT_FAILURE);
    }
    rc = regexec(&state,(char *)http,nmatch,pmatch,0);
    //rc = regexec(&state,string,nmatch,pmatch,0);
    regfree(&state);

    u_char data_buf[200];   //찾은 문자열 저장
    int jcheck=0;
    if(rc !=0){
            printf("Failed to match '%s' with '%s', returning %d. \n",http,pattern,rc);
            //printf("Failed to match '%s' with '%s', returning %d. \n",string,pattern,rc);
    }
    else {
        sprintf((char *)data_buf,"%s",&http[pmatch[1].rm_so]);
        //printf("시작 주소: %d :: 끝 주소:%d",&http[pmatch[1].rm_so],&http[pmatch[1].rm_eo]);
        //printf("길이 확인: %d \n",strlen(&http[pmatch[1].rm_so]));
        //sprintf(data_buf,"%s",&string[pmatch[1].rm_so]);
        printf("데이터 이동 확인: %s \n",data_buf);
        jcheck = jfopen(data_buf);
    }

    printf("구분선 ---------------------------------------------------------\n");
    if(jcheck==FIND)    NF=0;
    else NF=1;
}



/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);
        //dump(data,ret);
        check(data);



    fputc('\n', stdout);

    return (uint32_t)id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    //printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%d \n",NF);
    return nfq_set_verdict(qh, id, NF, 0, NULL);
}

int main(int argc, char *argv[])
{
    fp = fopen("/root/Desktop/ccit/1m_detect/top-1m","r");
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }




    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }






    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. Please, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);
    exit(0);
}
