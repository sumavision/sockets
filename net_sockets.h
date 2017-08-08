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

//sockets 域
#define SOCK_AF_IPv4             AF_INET
#define SOCK_AF_IPv6             AF_INET6
#define SOCK_AF_UNIX             AF_UNIX
#define SOCK_AF_UNSPEC           AF_UNSPEC
//sockets 类型
#define SOCK_UDP_DGRAM           SOCK_DGRAM
#define SOCK_TCP_STREAM          SOCK_STREAM
#define SOCK_IP_API              SOCK_RAW
//sockets 协议
#define SOCK_PROTO_TCP           IPPROTO_TCP
#define SOCK_PROTO_UDP           IPPROTO_UDP
#define SOCK_PROTO_IPv4          IPPROTO_IP
#define SOCK_PROTO_IPv6          IPPROTO_IPv6
#define SOCK_PROTO_UNSPEC        0
//sockets 选项
#define SOCK_LEVEL_SOCKET        SOL_SOCKET
#define SOCK_OPT_LISTEN          SO_ACCEPTCONN         //int,是否能被监听，仅供查询
#define SOCK_OPT_BROADCAST       SO_BROADCAST          //int,广播数据包
#define SOCK_OPT_DEBUG           SO_DEBUG              //int,启用网络驱动调试功能
#define SOCK_OPT_DONTROUTE       SO_DONTROUTE          //int,绕过通常路由
#define SOCK_OPT_ERROR           SO_ERROR              //int,返回挂起的套接字错误并清除
#define SOCK_OPT_KEEPALIVE       SO_KEEPALIVE          //int,启用周期性keep-alive消息
#define SOCK_OPT_LINGER          SO_LINGER             //struct linger,未发消息并且套接字关闭时延迟时间
#define SOCK_OPT_OOBINLINE       SO_OOBINLINE          //int,将带外数据放到普通数据中
#define SOCK_OPT_RCVBUF          SO_RCVBUF             //int,以字节为单位的接收缓冲区大小
#define SOCK_OPT_RCVLOWAT        SO_RCVLOWAT           //int,接收调用中返回的以字节为单位的最小数据量
#define SOCK_OPT_RCVTIMEO        SO_RCVTIMEO           //struct timeval,接收调用的超时值
#define SOCK_OPT_REUSEADDR       SO_REUSEADDR          //int,重用bind的地址
#define SOCK_OPT_SNDBUF          SO_SNDBUF             //int,以字节为单位的发送缓冲区大小
#define SOCK_OPT_SNDLOWAT        SO_SNDLOWAT           //int,发送调用中以字节为单位的发送的最小数据量
#define SOCK_OPT_SNDTIMEO        SO_SNDTIMEO           //struct timeval，发送调用的超时值
#define SOCK_OPT_TYPE            SO_TYPE               //int,标识套接字类型，仅供查询

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
	/*是否使用此套接字选项*/
	char flag;
	int optState;
}SOCK_OPT;

typedef struct _SOCK_PARAM_
{
	/*套接字通信域*/
	int addr_family;
	/*套接字类型*/
	int sock_type;
	/*通信协议 TCP UDP*/
	int protocol;

	/*IP*/
	int AddrIP;
	/*端口号*/
	int port;

	/*接收标志，用于改变接收的默认行为,一般为0*/
	int RecvFlags;
	/*发送标志，用于改变发送的默认行为,一般为0*/
	int SndFlags;
}SOCK_PARAM;
typedef struct _SOCK_BUFF_OBJ_
{
	/*接收buff*/
	void *RecvBuff;
	/*接收buff 大小*/
	int RecvBuffLen;
	/*当前接收数据 大小*/
	int RecvDataLen;
	/*返回buff*/
	void *SndBuff;
	/*返回buff 大小*/
	int SndBuffLen;
	/*当前返回数据 大小*/
	int SndDataLen;
}SOCK_BUFF_OBJ;

typedef struct _SOCK_OBJ_
{
    SOCK_PARAM params;

	SOCK_BUFF_OBJ sock_buff;

	/*线程结束控制*/
	char exit_ctrl;
	/*本地套接字搜寻控制*/
	char sock_connect_ctrl;
	/*数据接收控制*/
	char sock_recv_ctrl;
	/*发送 or 接收*/
	char sock_recv_snd;
	/*数据解析发送结束标志*/
	char sock_snd_flag;

	/*套接字选项*/
	SOCK_OPT opt[SOCK_OPT_NUM];
	int CurrOptNum;

	/*线程stack size*/
	int tsk_stack_size;
	/*线程ID*/
	pthread_t tsk_id;

	/*客户机地址信息*/
	struct sockaddr_storage	clntAddr;
	/*存储地址的结构体长度*/
	socklen_t			    clntLen;

	pthread_mutex_t mux; 
}SOCK_OBJ;

//用于外部初始化
typedef struct _SOCK_INIT_PARAMS_
{
	SOCK_PARAM params;

	/*套接字选项列表*/
	int OptList[SOCK_OPT_NUM];
	int CurrOptNum;

	/*接收buff 大小*/
	int RecvBuffLen;
	/*返回buff 大小*/
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

