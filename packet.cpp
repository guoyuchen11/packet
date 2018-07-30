#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<string.h>
#include<unistd.h>
#include<assert.h>
#include<error.h>
#include<iostream>
using namespace std;

#include<sys/socket.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>
#include<linux/if_arp.h>
#include<pthread.h>
#include<semaphore.h>
#include<sys/shm.h>
#include<queue>

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

sem_t semid;
pthread_mutex_t mutex;
queue<char*> que;

void handle(char* buff,int i);




void* pthread_fun(void* arg)
{
	int i=(int)arg;
	while(1)
	{
//		pthread_mutex_lock(&mutex);
		sem_wait(&semid);
		if(!que.empty())
		{
//			sem_wait(&semid);
			char* buff=que.front();
			handle(buff,i);
			que.pop();
//			sem_post(&semid);
			delete[] buff;
			buff=NULL;
		}
		sem_post(&semid);
//		pthread_mutex_unlock(&mutex);
	}
}




int main()
{
	sem_init(&semid,0,1);
	pthread_mutex_init(&mutex,NULL);

	int sock=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
	if(sock<0)
	{
		perror("socket");
		return 0;
	}

	int i=0;
	for(;i<4;++i)
	{
		pthread_t id;
		int res=pthread_create(&id,NULL,pthread_fun,(void*)i);
		assert(res==0);
	}


	while(1)
	{
		char* p=new char[1514];
		memset(p,0,1514);
		int ret=read(sock,p,1514);
		if(ret<=0)
		{
			perror("read error");
			return 0;
		}
		sem_wait(&semid);
		que.push(p);
		sem_post(&semid);

	}
	sem_destroy(&semid);

	return 0;
}






void handle(char* buff,int i)
{
	//MAC前12位直接偏移，之后2位判断？=0x0800
	char* now=buff;
	now=buff+12;
	if(ETH_P_IP!=ntohs(*((unsigned short*)now)))
	{
		perror("IP error");
		return ;
	}
	now=now+2;
	//ip
//  char* ip_ptr=now;

	IPhead* iphead=(IPhead*)now;
	struct sockaddr_in source,dest;
	source.sin_addr.s_addr=iphead->source_ip;
	dest.sin_addr.s_addr=iphead->dest_ip;

	if(strncmp(inet_ntoa(source.sin_addr),"127.0.0.1",9)!=0)
	{
		return ;
	}
	cout<<"thread index   "<< i << endl;

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
	cout<<endl;
	cout<<"tcpt头部信息"<<endl;
	cout<<"源端口号："<<ntohs(tcphead->source_tcp)<<endl;
	cout<<"目的端口号："<<ntohs(tcphead->dest_tcp)<<endl;
	cout<<"序列号:  "<<ntohl(tcphead->seq_num)<<endl;
	cout<<"确认号："<<ntohl(tcphead->Ack_num)<<endl;

	cout<<"FIN:    "<<tcphead->FIN<<"     ";
	cout<<"SYN:    "<<tcphead->SYN<<"     ";
	cout<<"RST:    "<<tcphead->RST<<"     ";
	cout<<"PSH:    "<<tcphead->PSH<<"     ";
	cout<<"ACK:    "<<tcphead->ACK<<"     ";
	cout<<"URG:    "<<tcphead->URG<<"     ";
	cout<<endl;
	//数据
	char* data=now;
	printf("数据：%s\n",data);

//	sem_post(&semid);
}









