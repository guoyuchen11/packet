#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<string.h>
#include<unistd.h>
#include<assert.h>
#include<error.h>

#include<sys/socket.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>
#include<linux/if_arp.h>

typedef struct IPhead
{
	unsigned int head_len:4,
				 version:4,
	             serve_type:8,
				 totol_len:16;
	unsigned int sign:16,
				 signer:3,
				 pianyi:13;
	unsigned int livetime:8,
				 protocol:8,
				 head_check:16;
	unsigned int source_ip:32;
	unsigned int dest_ip:32;
}IPhead;

typedef struct TCPhead
{
	unsigned int source_tcp:16,
				 dest_tcp:16;
	unsigned int seq_num:32;
	unsigned int Ack_num:32;
	unsigned int retain_1:4,
				 head_len:4,
				 FIN:1,
				 SYN:1,
				 RST:1,
				 PSH:1,
				 ACK:1,
				 URG:1,
				 retain_2:2,
				 window:16;
	unsigned int check_add:16,
				 emg_ptr:16;
}TCPhead;


int handle(char* buff,int ret)
{
	//MAC前12位直接偏移，之后2位判断？=0x0800
	char* now=buff;
	now=buff+12;
//	char* macptr=now;
	if(ETH_P_IP!=ntohs(*((unsigned short*)now)))
	{
		perror("IP error");
		return 0;
	}
	now=now+2;
	printf("00000000000\n");
	//ip
//  char* ip_ptr=now;

	IPhead* iphead=(IPhead*)now;
	struct sockaddr_in source,dest;
	source.sin_addr.s_addr=iphead->source_ip;
	dest.sin_addr.s_addr=iphead->dest_ip;

	printf("********************协议：tcp***********************\n");
	printf("ip头部信息\n");
	printf("源地址：%s\n",inet_ntoa(source.sin_addr));
	printf("目的地址：%s\n",inet_ntoa(dest.sin_addr));
	int iphead_len=iphead->head_len*4;
	now=now+iphead_len;             

	//tcp
//	char* tcp_ptr=now;
	TCPhead* tcphead=(TCPhead*)now;

/*	if(ntohs(iphead->source_ip)!=6000 && ntohs(iphead->dest_ip)!=6000)
	{
		printf("没有6000\n");
		return 0;
	}
*/
	int tcphead_len=tcphead->head_len*4;
	now=now+tcphead_len;
	printf("\n");
	printf("tcpt头部信息\n");
	printf("源端口号：%d\n",ntohs(tcphead->source_tcp));
	printf("目的端口号：%d\n",ntohs(tcphead->dest_tcp));
	printf("序列号：%d     ",ntohl(tcphead->seq_num));
	printf("确认号：%d\n",ntohl(tcphead->Ack_num));

	printf("FIN:%d    ",tcphead->FIN);
	printf("SYN:%d    ",tcphead->SYN);
	printf("RST:%d    ",tcphead->RST);
	printf("PSH:%d    ",tcphead->PSH);
	printf("ACK:%d    ",tcphead->ACK);
	printf("URG:%d    ",tcphead->URG);
	printf("\n");

	//数据
	char* data=now;
	printf("数据：%s\n",data);
}

int main()
{
	int sock=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
	if(sock<0)
	{
		perror("socket");
		return 0;
	}

	while(1)
	{
		char buff[1514]={0};
		int ret=read(sock,buff,sizeof(buff));
		if(ret<=0)
		{
			perror("read error");
			return 0;
		}
		handle(buff,ret);
	}
}
