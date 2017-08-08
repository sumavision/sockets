#ifndef _PTHREAD_NET_SOCKETS_H_
#define _PTHREAD_NET_SOCKETS_H_

#if defined (__cplusplus)
    extern "C" {
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#define SOCK_DEFAULT_IP          INADDR_ANY
#define SOCK_DEFAULT_PORT        4000

#define SOCK_OPT_NUM             50
#define SOCK_BUFF_SIZE           1024

//sockets ��
#define SOCK_AF_IPv4             AF_INET
#define SOCK_AF_IPv6             AF_INET6
#define SOCK_AF_UNIX             AF_UNIX
#define SOCK_AF_UNSPEC           AF_UNSPEC
//sockets ����
#define SOCK_UDP_DGRAM           SOCK_DGRAM
#define SOCK_TCP_STREAM          SOCK_STREAM
#define SOCK_IP_API              SOCK_RAW
//sockets Э��
#define SOCK_PROTO_TCP           IPPROTO_TCP
#define SOCK_PROTO_UDP           IPPROTO_UDP
#define SOCK_PROTO_IPv4          IPPROTO_IP
#define SOCK_PROTO_IPv6          IPPROTO_IPv6
#define SOCK_PROTO_UNSPEC        0
//sockets ѡ��
#define SOCK_LEVEL_SOCKET        SOL_SOCKET
#define SOCK_OPT_LISTEN          SO_ACCEPTCONN         //int,�Ƿ��ܱ�������������ѯ
#define SOCK_OPT_BROADCAST       SO_BROADCAST          //int,�㲥���ݰ�
#define SOCK_OPT_DEBUG           SO_DEBUG              //int,���������������Թ���
#define SOCK_OPT_DONTROUTE       SO_DONTROUTE          //int,�ƹ�ͨ��·��
#define SOCK_OPT_ERROR           SO_ERROR              //int,���ع�����׽��ִ������
#define SOCK_OPT_KEEPALIVE       SO_KEEPALIVE          //int,����������keep-alive��Ϣ
#define SOCK_OPT_LINGER          SO_LINGER             //struct linger,δ����Ϣ�����׽��ֹر�ʱ�ӳ�ʱ��
#define SOCK_OPT_OOBINLINE       SO_OOBINLINE          //int,���������ݷŵ���ͨ������
#define SOCK_OPT_RCVBUF          SO_RCVBUF             //int,���ֽ�Ϊ��λ�Ľ��ջ�������С
#define SOCK_OPT_RCVLOWAT        SO_RCVLOWAT           //int,���յ����з��ص����ֽ�Ϊ��λ����С������
#define SOCK_OPT_RCVTIMEO        SO_RCVTIMEO           //struct timeval,���յ��õĳ�ʱֵ
#define SOCK_OPT_REUSEADDR       SO_REUSEADDR          //int,����bind�ĵ�ַ
#define SOCK_OPT_SNDBUF          SO_SNDBUF             //int,���ֽ�Ϊ��λ�ķ��ͻ�������С
#define SOCK_OPT_SNDLOWAT        SO_SNDLOWAT           //int,���͵��������ֽ�Ϊ��λ�ķ��͵���С������
#define SOCK_OPT_SNDTIMEO        SO_SNDTIMEO           //struct timeval�����͵��õĳ�ʱֵ
#define SOCK_OPT_TYPE            SO_TYPE               //int,��ʶ�׽������ͣ�������ѯ

typedef enum
{
	SOCK_RECV_ONLY = 0,
	SOCK_SEND_ONLY,
	SOCK_RECV_SEND
}SOCK_RS_CTRL;

typedef void* sockets_handle;

typedef struct _SOCK_OPTION_
{
	int level;
	int optName;
	void* val;
	socklen_t optLen;
	char optStr[31];
	/*�Ƿ�ʹ�ô��׽���ѡ��*/
	char flag;
	int optState;
}SOCK_OPT;

typedef struct _SOCK_PARAM_
{
	/*�׽���ͨ����*/
	int addr_family;
	/*�׽�������*/
	int sock_type;
	/*ͨ��Э�� TCP UDP*/
	int protocol;

	/*IP*/
	int AddrIP;
	/*�˿ں�*/
	int port;

	/*���ձ�־�����ڸı���յ�Ĭ����Ϊ,һ��Ϊ0*/
	int RecvFlags;
	/*���ͱ�־�����ڸı䷢�͵�Ĭ����Ϊ,һ��Ϊ0*/
	int SndFlags;
}SOCK_PARAM;
typedef struct _SOCK_BUFF_OBJ_
{
	/*����buff*/
	void *RecvBuff;
	/*����buff ��С*/
	int RecvBuffLen;
	/*��ǰ�������� ��С*/
	int RecvDataLen;
	/*����buff*/
	void *SndBuff;
	/*����buff ��С*/
	int SndBuffLen;
	/*��ǰ�������� ��С*/
	int SndDataLen;
}SOCK_BUFF_OBJ;

typedef struct _SOCK_OBJ_
{
    SOCK_PARAM params;

	SOCK_BUFF_OBJ sock_buff;

	/*�߳̽�������*/
	char exit_ctrl;
	/*�����׽�����Ѱ����*/
	char sock_connect_ctrl;
	/*���ݽ��տ���*/
	char sock_recv_ctrl;
	/*���� or ����*/
	char sock_recv_snd;
	/*���ݽ������ͽ�����־*/
	char sock_snd_flag;

	/*�׽���ѡ��*/
	SOCK_OPT opt[SOCK_OPT_NUM];
	int CurrOptNum;

	/*�߳�stack size*/
	int tsk_stack_size;
	/*�߳�ID*/
	pthread_t tsk_id;

	/*�ͻ�����ַ��Ϣ*/
	struct sockaddr_storage	clntAddr;
	/*�洢��ַ�Ľṹ�峤��*/
	socklen_t			    clntLen;

	pthread_mutex_t mux; 
}SOCK_OBJ;

//�����ⲿ��ʼ��
typedef struct _SOCK_INIT_PARAMS_
{
	SOCK_PARAM params;

	/*�׽���ѡ���б�*/
	int OptList[SOCK_OPT_NUM];
	int CurrOptNum;

	/*����buff ��С*/
	int RecvBuffLen;
	/*����buff ��С*/
	int SndBuffLen;
	
	char sock_recv_snd;
} SOCK_INIT;

sockets_handle sock_server_create(SOCK_INIT *SockInit);
pthread_t sock_server_start(sockets_handle h,int priority);
void sock_server_delete(sockets_handle h);

void sock_snd_flag_set(sockets_handle h,char state);
char sock_snd_flag_get(sockets_handle h);

#if defined (__cplusplus)
}
#endif

#endif

