#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <sched.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
#include <unistd.h>
//#include <sys/socket.h>
#include <netdb.h>
#include "net_sockets.h"
/****************************************************************************************
 *                         static
 ****************************************************************************************/
static int rpt_lvl = 2; /* report level: ERR, WRN, INF, DBG */
static SOCK_PARAM sock_params_default = 
{
	SOCK_AF_IPv4,
	SOCK_UDP_DGRAM,
	SOCK_PROTO_UDP,
	SOCK_DEFAULT_IP,
	SOCK_DEFAULT_PORT,
	0,
	0,
};
/****************************************************************************************
 *                        Define
 ****************************************************************************************/
 /* report level */
#define RPT_ERR (1) // error, system error
#define RPT_WRN (2) // warning, maybe wrong, maybe OK
#define RPT_INF (3) // important information
#define RPT_DBG (4) // debug information

/* report micro */
#define RPT(lvl, ...) \
    do { \
        if(lvl <= rpt_lvl) { \
            switch(lvl) { \
                case RPT_ERR: \
                    fprintf(stderr, "\"%s\" line %d [err]: ", __FILE__, __LINE__); \
                    break; \
                case RPT_WRN: \
                    fprintf(stderr, "\"%s\" line %d [wrn]: ", __FILE__, __LINE__); \
                    break; \
                case RPT_INF: \
                    fprintf(stderr, "\"%s\" line %d [inf]: ", __FILE__, __LINE__); \
                    break; \
                case RPT_DBG: \
                    fprintf(stderr, "\"%s\" line %d [dbg]: ", __FILE__, __LINE__); \
                    break; \
                default: \
                    fprintf(stderr, "\"%s\" line %d [???]: ", __FILE__, __LINE__); \
                    break; \
                } \
                fprintf(stderr, __VA_ARGS__); \
                fprintf(stderr, "\n"); \
        } \
    } while(0)

#ifndef OFFSET
#define OFFSET(structure, member) ((int) &(((structure *) 0) -> member))
#endif
#ifndef false
#define false 0
#endif

#ifndef true
#define true 1
#endif

#ifndef NULL
#define NULL 0
#endif

#define SOCK_TSK_STACK_SIZE 10*1024

#define MAX_CONNECT_NUM SOMAXCONN
/****************************************************************************************
 *                        Function
 ****************************************************************************************/
/*****************************************************************************************
* 函数名称: NetToTextStr
* 函数功能: 网络字节序的二进制IP地址转化成 点分十进制字符串
* 输入参数: AddrFamily: 需转换的地址的类型，IPv4 IPv6
           addr     : 网络字节序的二进制IP地址
           NameZize : 点分十进制地址字符串大小
* 输出参数: AddrName : 指向转换后点分十进制地址字符串；大小由NameZize指定
* 返回结果: -1:转换失败；0:转换成功
* 修改记录:
******************************************************************************************/
 int NetToTextStr(int AddrFamily, unsigned int addr,char *AddrName,int NameZize)
{
	char ret = 0;

	if(AddrName == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	if(inet_ntop(AddrFamily,&addr,AddrName,NameZize) == NULL)
	{
		ret = -1;
	}
	
	return ret;
}
/*****************************************************************************************
* 函数名称: TextStrToNet
* 函数功能: 点分十进制字符串转化成二进制IP地址网络字节序
* 输入参数: 
* 输出参数: 
* 返回结果: 成功返回1；未被格式化为有效地址返回0；指定的地址族未知返回-1
* 修改记录:
******************************************************************************************/
 int TextStrToNet(int AddrFamily,char *AddrName,unsigned int* addr)
{
	char ret = 0;

	if(AddrName == NULL || addr == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}
		
	ret = inet_pton(AddrFamily,AddrName,addr);

	return ret;
}
/*****************************************************************************************
* 函数名称: sock_print_addr
* 函数功能: 打印IP地址与端口号
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
 int sock_print_addr(struct sockaddr *Addr,char *RptStr)
{
	char ret = 0;
		
	struct sockaddr_in *pCAddr;

	char AddrName[50] = {0};

	int AddrF = 0;

	if(Addr == NULL || RptStr == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	pCAddr = (struct sockaddr_in *)Addr;
	AddrF   = pCAddr->sin_family;
	ret = NetToTextStr(AddrF,pCAddr->sin_addr.s_addr,AddrName,sizeof(AddrName));
	if (ret != -1)
	{
		RPT(RPT_WRN,"%s %s/%d",RptStr,AddrName,ntohs(pCAddr->sin_port));
	}

	return ret;
}
 /*****************************************************************************************
* 函数名称: sock_close
* 函数功能: 关闭套接字
* 输入参数: 
* 输出参数: 无
* 返回结果: 无
* 修改记录:
******************************************************************************************/
static void sock_close(int socket_fd)
{
	if(socket_fd > 0)
		close(socket_fd);
}
 /*****************************************************************************************
* 函数名称: sock_create
* 函数功能: 创建套接字
* 输入参数: AddrFamily:地址类型，其值可为SOCK_AF_IPv4、SOCK_AF_IPv6等
           SockType :套接字类型，其值可为SOCK_UDP_DGRAM、SOCK_TCP_STREAM等
           SockProto :协议，其值可为SOCK_PROTO_TCP、SOCK_PROTO_UDP等
* 输出参数: 无
* 返回结果: 创建成功返回套接字描述符；否则返回-1
* 修改记录:
******************************************************************************************/
static int sock_create(int AddrFamily,int SockType,int SockProto)
{
	int socket_fd = -1;

	socket_fd = socket(AddrFamily,SockType, SockProto);

	return socket_fd;
}
 /*****************************************************************************************
* 函数名称: sock_bind
* 函数功能: 将套接字与服务器地址绑定
* 输入参数: SockFd : 套接字描述符
           ServAddr :指向服务器的一个地址，包含IP地址与端口
* 输出参数: 无
* 返回结果: 绑定成功返回0；失败返回-1
* 修改记录:
******************************************************************************************/
static int sock_bind(int SockFd,struct addrinfo* ServAddr)
 {
 	int ret = 0;

	if(ServAddr == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	ret = bind(SockFd,ServAddr->ai_addr,ServAddr->ai_addrlen);

	return ret;
 }
/*****************************************************************************************
* 函数名称: sock_listen
* 函数功能: 实现侦听来自客户的连接请求
* 输入参数: 
* 输出参数: 
* 返回结果: 成功 0；失败 -1
* 修改记录:
******************************************************************************************/
static int sock_listen(int SockFd)
 {
 	int ret = 0;

	ret = listen(SockFd,MAX_CONNECT_NUM);

	return ret;
 }

/*****************************************************************************************
* 函数名称: sock_accept
* 函数功能: 获得连接请求并建立连接
* 输入参数: 
* 输出参数: 
* 返回结果: 成功返回套接字描述符；失败返回-1
* 修改记录:
******************************************************************************************/
static int sock_accept(int SockFd)
 {
 	int ClntSock = 0;
	socklen_t			clntLen;
	struct sockaddr clntAddr;

	clntLen = sizeof(clntAddr);
	ClntSock = accept(SockFd,&clntAddr, &clntLen);
	if (ClntSock < 0)
	{
		return -1;
	}

	sock_print_addr(&clntAddr,"client addr ");
	
	return ClntSock;
 }

 /*****************************************************************************************
* 函数名称: sock_recv
* 函数功能: 接收数据
* 输入参数: SockFd:套接字描述符；size:此次可接收的最大字节数; 
           flags:改变套接字调用的默认行为的某些方面，一般为0
* 输出参数: buff :指向接收数据的存储空间
* 返回结果: 接收成功返回此次接收的数据大小；失败返回-1
* 修改记录:
******************************************************************************************/
static int sock_recv(int SockFd,void *buff,int size,int flags)
 {
 	int RecvSize = 0;

	if(buff == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	RecvSize = recv(SockFd,buff,size,flags);

	return RecvSize;
 }
/*****************************************************************************************
* 函数名称: sock_recv_from_clntAddr
* 函数功能: 从指定地址的客户端接收数据
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_recv_from_clntAddr(int SockFd,void *buff,int size,int flags,
		                                    struct sockaddr *ClntAddr,socklen_t *ClntAddrLen)
 {
 	int ret = 0;

	if(buff == NULL || ClntAddr == NULL ||ClntAddrLen == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	ret = recvfrom(SockFd,buff,size,flags,ClntAddr,ClntAddrLen);

	return ret;
 }
/*****************************************************************************************
* 函数名称: sock_send
* 函数功能: 发送数据
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_send(int SockFd,void *buff,int size,int flags)
 {
 	int RecvSize = 0;

	if(buff == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	RecvSize = send(SockFd,buff,size,flags);

	return RecvSize;
 }
/*****************************************************************************************
* 函数名称: sock_send_to_clntAddr
* 函数功能: 发送到指定地址的客户端
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_send_to_clntAddr(int SockFd,void *buff,int size,int flags,
		                                    struct sockaddr *ClntAddr,socklen_t ClntAddrLen)
 {
 	int ret = 0;

	if(buff == NULL ||ClntAddr == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	ret = sendto(SockFd,buff,size,flags,ClntAddr,ClntAddrLen);

	return ret;
 }
/*****************************************************************************************
* 函数名称: sock_option_set
* 函数功能: 设置套接字选项
* 输入参数: 
* 输出参数: 
* 返回结果: 成功返回0；出错返回-1
* 修改记录:
******************************************************************************************/
static int sock_option_set(int SockFd,int level,int opt,void* val,socklen_t optLen)
{
	int ret = 0;

	if(val == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	ret = setsockopt(SockFd,level,opt,val,optLen);

	return ret;
}
/*****************************************************************************************
* 函数名称: sock_option_get
* 函数功能: 查询某个套接字选项状态
* 输入参数: 
* 输出参数: 
* 返回结果: 成功返回0；出错返回-1
* 修改记录:
******************************************************************************************/
static int sock_option_get(int SockFd,int level,int opt,void* val,socklen_t *optLen)
{
	int ret = 0;

	if(val == NULL ||optLen == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	ret = getsockopt(SockFd,level,opt,val,optLen);

	return ret;
}
/*****************************************************************************************
* 函数名称: sock_opt_list_set
* 函数功能: 初始化各套接字选项属性
* 输入参数: 
* 输出参数: 
* 返回结果: 成功返回0；出错返回-1
* 修改记录:
******************************************************************************************/
static int sock_opt_list_set(SOCK_OBJ *h,int sock_fd)
{
	int ret = 0;
	int i = 0;

	SOCK_OPT *pSockOpt = NULL;
	int OptNum = 0;

	if(h == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}
	
	RPT(RPT_WRN, "socket opt set start");
	OptNum = h->CurrOptNum;
	for (i = 0;i < OptNum;i++)
	{
		pSockOpt = &(h->opt[i]);
		if (pSockOpt->flag == 0x5a)
		{
			ret = sock_option_set(sock_fd,pSockOpt->level,pSockOpt->optName,
				                  pSockOpt->val,pSockOpt->optLen);
			if (ret < 0)
			{
				RPT(RPT_ERR, "socket opt set (%s) fail",pSockOpt->optStr);
				break;
			}
			RPT(RPT_WRN, "socket opt set (%s) success",pSockOpt->optStr);
		}
	}

	return ret;
}
/*****************************************************************************************
* 函数名称: sock_is_ready
* 函数功能: 描述符是否已经准备好
* 输入参数: socket_fd:套接字描述符，timeout:超时控制时间值
* 输出参数: 无
* 返回结果: 准备就绪的描述符数目，超时返回0，出错返回-1
* 修改记录:
******************************************************************************************/
static int sock_is_ready(int socket_fd, uint32_t timeout/*ms*/)
{
	fd_set fdset;

	int ret = 0;
	
	struct timeval timeval;
	memset(&timeval, 0, sizeof(struct timeval));
	timeval.tv_sec = timeout / 1000;
	timeval.tv_usec = (timeout % 1000) * 1000;

	//将fdset所有位均置为0(描述符状态清零)
	FD_ZERO(&fdset);
	//将socket_fd描述符位置1
	FD_SET(socket_fd, &fdset);

	//描述符是否可读
	ret = select(socket_fd + 1, &fdset, NULL, NULL, &timeval);
	if(ret < 0)
	{
		RPT(RPT_ERR, "socket_fd select error");
		return -1;
	}
	else if (ret == 0)
	{
		RPT(RPT_ERR, "socket_fd select not ready");
		return 0;
	}

	//测试描述符是否仍旧设置
	if(FD_ISSET(socket_fd, &fdset) == 0)
	{
		RPT(RPT_ERR, "socket_fd not set");
		return  0;
	}

	return ret;
}
/*****************************************************************************************
* 函数名称: sock_snd_flag_set
* 函数功能: 数据是否解析完成并准备发送的标志
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
void sock_snd_flag_set(sockets_handle h,char state)
{
	SOCK_OBJ *handle = h;
	
	pthread_mutex_lock(&handle->mux);
	handle->sock_snd_flag = state;
	pthread_mutex_unlock(&(handle->mux));
}
/*****************************************************************************************
* 函数名称: sock_snd_flag_get
* 函数功能: 查询发送数据是否完成的标志
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
char sock_snd_flag_get(sockets_handle h)
{
	SOCK_OBJ *handle = h;
	char state = 0;
	
	state = handle->sock_snd_flag ;

	return state;
}
 /*****************************************************************************************
* 函数名称: sock_addr_list_get
* 函数功能: 服务器地址列表的获取；允许将一个主机和服务名字映射到一个地址
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_addr_list_get(SOCK_PARAM* SocketParam,struct addrinfo** AddrList)
 {
	int ret = 0;

	char PortStr[10] = {0};
	char LocalAddr[50] = {0};

	unsigned int LocalIPNet = 0;
	
 	struct addrinfo HintAddr;
	memset(&HintAddr,0,sizeof(HintAddr));

	if(SocketParam == NULL || AddrList == NULL || *AddrList == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	//端口号字符串
	sprintf(PortStr,"%d",SocketParam->port);
	//ip地址字符串格式
	LocalIPNet = htonl(SocketParam->AddrIP);
	if (NetToTextStr(SocketParam->addr_family,LocalIPNet,LocalAddr,sizeof(LocalAddr)) == -1)
	{
		RPT(RPT_ERR,"AddrIP str get fail");
		return -1;
	}
	//IPv4 IPv6 均适用
	HintAddr.ai_family = SOCK_AF_UNSPEC;  
	//任何addr/port均接受
	HintAddr.ai_flags = AI_PASSIVE;          
	HintAddr.ai_socktype = SocketParam->sock_type;
	HintAddr.ai_protocol = SocketParam->protocol;

	RPT(RPT_WRN,"Local addr %d=%d %s/%s",SocketParam->AddrIP,LocalIPNet,LocalAddr,PortStr);

	ret = getaddrinfo(LocalAddr,PortStr,&HintAddr,AddrList);

	return ret;
 }
 /*****************************************************************************************
* 函数名称: sock_server_init
* 函数功能: 搜寻地址列表，查找可用套接字，tcp 套接字创建 绑定 监听
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_server_init(SOCK_OBJ *handle ,struct addrinfo *List)
{
	int ret = -1;
	int sock_fd = -1;

	struct addrinfo *addr;

	if(handle == NULL || List == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}
	
	//搜寻地址列表，查找可用套接字，tcp 套接字创建 绑定 监听
	for (addr = List;addr != NULL;addr = addr->ai_next)
	{
		sock_fd = sock_create(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if(sock_fd < 0)
		{
			RPT(RPT_ERR, "socket create fail");
			continue;
		}

		ret = sock_opt_list_set(handle,sock_fd);
		if (ret < 0)
		{
			continue;
		}

		ret = sock_bind(sock_fd,addr);
		if(ret < 0)
		{
			sock_close(sock_fd);
			RPT(RPT_ERR, "bind fail");
			continue;
		}
		RPT(RPT_WRN, "bind success");

		if (addr->ai_socktype == SOCK_TCP_STREAM)
		{
			ret = sock_listen(sock_fd);
			if(ret < 0)
			{
				sock_close(sock_fd);
				RPT(RPT_ERR, "listen fail");
				continue;
			}
			RPT(RPT_WRN, "listen success");
		}
		//此处显示仅IPv4有效
		sock_print_addr(addr->ai_addr,"local addr ");
		//bind listen successful
		break;
	}

	//释放链表空间
	freeaddrinfo(List);
	if ( NULL == addr)
	{
		sock_fd = -1;
	}

	return sock_fd;
}
/*****************************************************************************************
* 函数名称: sock_Id_local_get
* 函数功能: 获取本地服务器的套接字描述符
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_Id_local_get(SOCK_OBJ *handle )
{
	int sock_fd = 0;
	int ret = 0;

	if(handle == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	struct addrinfo *AddrList;

	SOCK_PARAM *Params = NULL;
	Params = &(handle->params);
	
	ret = sock_addr_list_get(Params,&AddrList);
	if (ret != 0)
	{
		RPT(RPT_ERR,"addrinfo list get fail");
		return -1;
	}

	sock_fd = sock_server_init(handle,AddrList);
	if (sock_fd < 0)
	{
		RPT(RPT_ERR,"sock server init fail");
		ret = 0;
	}

	if (Params->protocol == SOCK_PROTO_TCP)
	{
		RPT(RPT_WRN,"tcp sock init success %d",sock_fd);

	}
	else if (Params->protocol == SOCK_PROTO_UDP)
	{
		RPT(RPT_WRN,"udp sock init success %d",sock_fd);
	}
	
	ret = sock_fd;
	return ret;
}
/*****************************************************************************************
* 函数名称: sock_stream_recv_package
* 函数功能: 流套接字接收数据
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_stream_recv_package(SOCK_OBJ * SockObj,int sock_fd,int *ClntFd)
{
	int ClntSockFd = 0;
	int BuffSize = 0;
	int RecvLen = 0;
	int flags = 0;

	void *pBuff = NULL;

	SOCK_BUFF_OBJ *pSockBuff = NULL;

	if(SockObj == NULL || ClntFd == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}
	
	ClntSockFd = sock_accept(sock_fd);
	if (ClntSockFd < 0)
	{
		RPT(RPT_ERR,"local socket %d accept failed %d",sock_fd,ClntSockFd);
		return -1;
	}
	RPT(RPT_WRN,"accept success %d",ClntSockFd);

	if (SockObj->sock_recv_snd == SOCK_SEND_ONLY)
	{
		RPT(RPT_WRN,"sock send only");
		return RecvLen;
	}
	*ClntFd = ClntSockFd;
	
	pSockBuff= &(SockObj->sock_buff);
	pBuff     = pSockBuff->RecvBuff;
	BuffSize  = pSockBuff->RecvBuffLen;
	flags     = SockObj->params.RecvFlags;
	memset((char*)pBuff,0,pSockBuff->RecvDataLen);
	pSockBuff->RecvDataLen = 0;
	RPT(RPT_WRN,"recv buffsize %d = %d",BuffSize,RecvLen);
	while (RecvLen < BuffSize)
	{
		//描述符是否阻塞
		if (sock_is_ready(ClntSockFd,3000) <= 0)
		{
			return -1;
		}
		RecvLen = sock_recv(ClntSockFd,pBuff,BuffSize,flags);
		if(RecvLen < 0)
		{
			RPT(RPT_ERR, "recv data error");
			return -1;
		}
		if (RecvLen == 0)
		{
			RPT(RPT_ERR, "recv data finished");
			break;
		}
		RPT(RPT_WRN,"recv data %s",(char*)pBuff);
		pSockBuff->RecvDataLen += RecvLen;
		if(RecvLen < BuffSize)
		{
			pBuff += RecvLen;
			BuffSize -= RecvLen;
			RecvLen = 0;
		}
	}
	
	RPT(RPT_WRN, "recv data success");

	//sock_close(ClntSockFd);

	return RecvLen;
}
extern void ctrl_frame_to_string(char *CFBuff);
/*****************************************************************************************
* 函数名称: sock_dgram_recv_package
* 函数功能: 数据包套接字接收数据
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_dgram_recv_package(SOCK_OBJ *SockObj,int sock_fd, int *ClntFd)
{
	int BuffSize = 0;
	int RecvLen = 0;
	int flags = 0;

	void *pBuff = NULL;

	SOCK_BUFF_OBJ *pSockBuff = NULL;

	struct sockaddr *ClntAddr;
	socklen_t      ClntAddrLen;

	if(SockObj == NULL || ClntFd == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	if (SockObj->sock_recv_snd == SOCK_SEND_ONLY)
	{
		RPT(RPT_WRN,"sock send only");
		return RecvLen;
	}

	ClntAddr     = (struct sockaddr *)(&SockObj->clntAddr);
	ClntAddrLen  = SockObj->clntLen;

	*ClntFd   = sock_fd;
	
	pSockBuff= &(SockObj->sock_buff);
	pBuff     = pSockBuff->RecvBuff;
	BuffSize  = pSockBuff->RecvBuffLen;
	flags     = SockObj->params.RecvFlags;
	
	memset((char*)pBuff,0,pSockBuff->RecvDataLen);
	pSockBuff->RecvDataLen = 0;
	RecvLen = sock_recv_from_clntAddr(sock_fd, pBuff,BuffSize,flags,ClntAddr,&ClntAddrLen);
	if(RecvLen < 0)
	{
		RPT(RPT_ERR, "udp recv error");
		return -1;
	}
	RPT(RPT_WRN, "udp recv success %s",(char*)pBuff);

	SockObj->clntLen = ClntAddrLen;
	pSockBuff->RecvDataLen = RecvLen;

	//客户机地址信息打印 适用于IPv4
	sock_print_addr(ClntAddr,"client addr ");

	/************************* 打印 接收消息 *****************************/
	ctrl_frame_to_string(pBuff);

	return RecvLen;
}
/*****************************************************************************************
* 函数名称: sock_server_recv
* 函数功能: 套接字接收数据
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_server_recv(sockets_handle h,int sock_fd,int *ClntFd)
{
	SOCK_OBJ *handle = h;

	int len = 0;

	int type = handle->params.sock_type;

	if(ClntFd == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	if (type == SOCK_TCP_STREAM)
	{
		len = sock_stream_recv_package(handle,sock_fd,ClntFd);
	}
	else if (type == SOCK_UDP_DGRAM)
	{
		len = sock_dgram_recv_package(handle,sock_fd,ClntFd);
	}

	return len;
}
/*****************************************************************************************
* 函数名称: sock_stream_send_package
* 函数功能: 流套接字发送数据
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_stream_send_package(int sock_fd,SOCK_OBJ * SockObj)
{
	int DataSize = 0;
	int SndLen = 0;
	int flags = 0;

	void *pBuff = NULL;
	SOCK_BUFF_OBJ *pSockBuff = NULL;

	if(SockObj == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	pSockBuff= &(SockObj->sock_buff);
	pBuff     = pSockBuff->SndBuff;
	DataSize  = pSockBuff->SndDataLen;
	flags     = SockObj->params.SndFlags;
	SndLen = sock_send(sock_fd,pBuff,DataSize,flags);
	if (SndLen < 0)
	{
		RPT(RPT_ERR,"tcp sock send failed");
		return -1;
	}

	RPT(RPT_WRN, "tcp sock send success");
	return SndLen;
}
/*****************************************************************************************
* 函数名称: sock_dgram_send_package
* 函数功能: 数据包套接字发送数据
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_dgram_send_package(int sock_fd,SOCK_OBJ * SockObj)
{
	int DataSize = 0;
	int SndLen = 0;
	int flags = 0;

	void *pBuff = NULL;
	SOCK_BUFF_OBJ *pSockBuff = NULL;

	struct sockaddr *ClntAddr;
	socklen_t      ClntAddrLen;

	if(SockObj == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	ClntAddr     = (struct sockaddr *)(&SockObj->clntAddr);
	ClntAddrLen  = SockObj->clntLen;

	pSockBuff= &(SockObj->sock_buff);
	pBuff     = pSockBuff->SndBuff;
	DataSize  = pSockBuff->SndDataLen;
	flags     = SockObj->params.SndFlags;

	RPT(RPT_WRN, "udp sock send data %s/%d",(char*)pBuff,DataSize);
	//客户机地址信息打印 适用于IPv4
	sock_print_addr(ClntAddr,"client addr ");

	SndLen = sock_send_to_clntAddr(sock_fd, pBuff,DataSize,flags,ClntAddr,ClntAddrLen);
	if(SndLen < 0)
	{
		RPT(RPT_ERR, "udp sock send error");
		return -1;
	}
	
	RPT(RPT_WRN, "udp sock send success %d",SndLen);

	return SndLen;
}
/*****************************************************************************************
* 函数名称: sock_server_send
* 函数功能: 发送数据
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int sock_server_send(sockets_handle h,int sock_fd)
{
	SOCK_OBJ *handle = h;

	int len = 0;

	int type = handle->params.sock_type;
	
	if (type == SOCK_TCP_STREAM)
	{
		len = sock_stream_send_package(sock_fd,handle);
	}
	else if (type == SOCK_UDP_DGRAM)
	{
		len = sock_dgram_send_package(sock_fd,handle);
	}
	
	return len;
}
 /*****************************************************************************************
* 函数名称: sock_server_pthread
* 函数功能: 套接字线程
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static void sock_server_pthread(sockets_handle h)
 {
	int sock_fd = 0;
	int ClntSockFd = 0;

	int RecvLen = 0;
	int SndLen = 0;

	SOCK_OBJ *handle = h;
	
	handle->exit_ctrl = false;
	RPT(RPT_WRN,"***sock start***");
	while (handle->sock_connect_ctrl)
	{
		//获取本地套接字，并绑定本地地址与端口
		sock_fd = sock_Id_local_get(handle);
		if (sock_fd < 0)
		{
			break;
		}
		else if (0 == sock_fd)
		{
			continue;
		}
		//读取数据
		while (handle->sock_recv_ctrl)
		{
			RecvLen = sock_server_recv(h,sock_fd,&ClntSockFd);
			if (RecvLen<0)
			{
				break;
			}
			if (handle->sock_recv_snd != SOCK_SEND_ONLY)
			{
				RPT(RPT_WRN, "sock recv len = %d",RecvLen);
			}
			if (handle->sock_recv_snd == SOCK_RECV_ONLY)
			{
				RPT(RPT_WRN, "sock recv only");
				continue;
			}
			sock_snd_flag_set(h,false);
			
			//等待此次数据解析完毕后，发送返回结果包
			while(1)
			{
				if (sock_snd_flag_get(h) == true)
				{
					break;
				}
			}
			SndLen = sock_server_send(h,ClntSockFd);
			if (SndLen<0)
			{
				break;
			}
			RPT(RPT_WRN, "sock send len = %d",SndLen);

			//tcp accept 每次发送结束后应关闭套接字，udp不需
			if (handle->params.sock_type == SOCK_TCP_STREAM)
			{
				sock_close(ClntSockFd);
			}
		}
		
		sock_close(sock_fd);
	}
	sock_close(sock_fd);
	handle->exit_ctrl = true;
	
	RPT(RPT_ERR,"sock end");
 }
 /*****************************************************************************************
* 函数名称: sock_opt_struct_val
* 函数功能: 套接字选项列表
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static void sock_opt_struct_val(int optName,SOCK_INIT *sockInit,SOCK_OPT *pOpt)
 {
	if(sockInit == NULL || pOpt == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return;
	}
	
 	switch (optName)
	{
		case SOCK_OPT_RCVBUF:
			//套接字接收缓冲区大小
			pOpt->flag     = 0x5a;
			pOpt->level    = SOCK_LEVEL_SOCKET;
			pOpt->optName  = SOCK_OPT_RCVBUF;
			pOpt->val      = &(sockInit->RecvBuffLen);
			pOpt->optLen   = sizeof(sockInit->RecvBuffLen);
			strcpy(pOpt->optStr,"opt_RecvBuff");
			break;
		case SOCK_OPT_SNDBUF:
			//套接字发送缓冲区大小
			pOpt->flag     = 0x5a;
			pOpt->level    = SOCK_LEVEL_SOCKET;
			pOpt->optName  = SOCK_OPT_SNDBUF;
			pOpt->val      = &(sockInit->SndBuffLen);
			pOpt->optLen   = sizeof(sockInit->SndBuffLen);
			strcpy(pOpt->optStr,"opt_SndBuff"); 
			break;
		case SOCK_OPT_REUSEADDR:
			//套接字 bind 地址重用
			pOpt->flag     = 0x5a;
			pOpt->level    = SOCK_LEVEL_SOCKET;
			pOpt->optName  = SOCK_OPT_REUSEADDR;
			pOpt->optState 	= 1;
			pOpt->val      = &(pOpt->optState);
			pOpt->optLen   = sizeof(pOpt->optState);
			strcpy(pOpt->optStr,"opt_ReUse_Addr"); 
			break;
		case SOCK_OPT_BROADCAST:
			//套接字 允许广播
			pOpt->flag     = 0x5a;
			pOpt->level    = SOCK_LEVEL_SOCKET;
			pOpt->optName  = SOCK_OPT_BROADCAST;
			pOpt->optState 	= 1;
			pOpt->val      = &(pOpt->optState);
			pOpt->optLen   = sizeof(pOpt->optState);
			strcpy(pOpt->optStr,"opt_broad_cast"); 
			break;
		default :
			break;
	}
 }
 /*****************************************************************************************
* 函数名称: sock_opt_list_init
* 函数功能: 套接字选项列表
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static void sock_opt_list_init(SOCK_OBJ *handle,SOCK_INIT *sockInit)
{
	int i = 0;
	
	int pOptList = 0;

	SOCK_OPT *pSockOpt = NULL;

	if(sockInit == NULL || handle == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return;
	}
	
	for (i = 0;i < (sockInit->CurrOptNum);i++)
	{
		pSockOpt = (SOCK_OPT *)&(handle->opt[i]);
		pOptList = sockInit->OptList[i];
		sock_opt_struct_val(pOptList,sockInit,pSockOpt);
		RPT(RPT_WRN,"sock %s init success",pSockOpt->optStr);
	}

	handle->CurrOptNum = sockInit->CurrOptNum;
}
/*****************************************************************************************
* 函数名称: sock_server_create
* 函数功能: 套接字服务器的创建,结构体空间分配，各参数的配置
* 输入参数: 
* 输出参数: 
* 返回结果: 返回指向套接字结构体的句柄
* 修改记录:
******************************************************************************************/
sockets_handle sock_server_create(SOCK_INIT *SockInit)
{
	SOCK_OBJ *handle;
	SOCK_BUFF_OBJ *pSockBuff;

	if(SockInit == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return NULL;
	}

	handle = (SOCK_OBJ *)calloc(1,sizeof(SOCK_OBJ));
	if (NULL == handle)
	{
		RPT(RPT_ERR,"sock handle create failed");

		return handle;
	}
	RPT(RPT_WRN,"sock handle create success");

	//初始化接收发送buff
	pSockBuff = &(handle->sock_buff);
	pSockBuff->RecvBuffLen = SockInit->RecvBuffLen;
	pSockBuff->RecvDataLen = 0;
	pSockBuff->SndBuffLen = SockInit->SndBuffLen;
	pSockBuff->SndDataLen = 0;
#if 1
	pSockBuff->RecvBuff   = calloc(1,pSockBuff->RecvBuffLen);
	if (NULL == pSockBuff->RecvBuff)
	{
		RPT(RPT_ERR,"sock recvbuff create failed");
		return pSockBuff->RecvBuff;
	}

	pSockBuff->SndBuff = calloc(1,pSockBuff->SndBuffLen);
	if (NULL == pSockBuff->SndBuff)
	{
		RPT(RPT_ERR,"sock sndbuff create failed");

		return pSockBuff->SndBuff;
	}
#endif
	memset(pSockBuff->RecvBuff,0,pSockBuff->RecvBuffLen);
	memset(pSockBuff->SndBuff,0,pSockBuff->SndBuffLen);

	//sock 参数设置
	if (SockInit == NULL)
	{
		handle->params = sock_params_default;
	}
	else 
	{
		handle->params = SockInit->params;
	}

	handle->tsk_stack_size = SOCK_TSK_STACK_SIZE;

	//sock 线程控制参数设置
	handle->sock_connect_ctrl = true;
	handle->sock_recv_ctrl  = true;
	handle->sock_snd_flag   = true;
	handle->exit_ctrl       = true;

	handle->sock_recv_snd   = SockInit->sock_recv_snd;

	//套接字选项
	memset(handle->opt,0,sizeof(handle->opt));
	RPT(RPT_WRN,"sock opt len %d",sizeof(handle->opt));
	sock_opt_list_init(handle,SockInit);

	handle->clntLen = sizeof(handle->clntAddr);
	memset((char*)&handle->clntAddr,0,handle->clntLen);
	
	memset(&(handle->mux), 0,sizeof(pthread_mutex_t));
	pthread_mutex_init(&(handle->mux), NULL);

	return handle;
}
/*****************************************************************************************
* 函数名称: sock_server_delete
* 函数功能: 套接字线程关闭
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
void sock_server_delete(sockets_handle h)
{
	SOCK_OBJ *handle = h;
	SOCK_BUFF_OBJ *SockBuff = NULL;

	int wait_nums = 0; 

	if(handle == NULL)
    {
        RPT(RPT_ERR," sock delete NULL pointer");
        return;
    }

	handle ->sock_connect_ctrl = false;
	handle ->sock_recv_ctrl  = false;
	sock_snd_flag_set(h,false);

	//等待线程结束
	while (handle ->exit_ctrl == false)
	{
		wait_nums++;
		sock_is_ready(0,10000);
		if(wait_nums > 100)
		{
			RPT(RPT_WRN," sock_delete wait time out");
			wait_nums = 0;
		}

		handle ->sock_connect_ctrl = false;
		handle ->sock_recv_ctrl  = false;
		sock_snd_flag_set(h,false);
	}

	pthread_mutex_destroy(&handle->mux);
#if 1
	SockBuff = &handle->sock_buff;
	if (SockBuff->RecvBuff)
	{
		memset(SockBuff->RecvBuff,0,SockBuff->RecvBuffLen);
		free(SockBuff->RecvBuff);
	}
	if (SockBuff->SndBuff)
	{
		memset(SockBuff->SndBuff,0,SockBuff->SndBuffLen);
		free(SockBuff->SndBuff);
	}
#endif
	memset(handle,0,sizeof(SOCK_OBJ));
	free(handle);
	
	if(handle->tsk_id != 0)
	{
		pthread_join( handle->tsk_id, NULL );
	}
	
	RPT(RPT_WRN,"sock_delete end");
}
 /*****************************************************************************************
* 函数名称: sock_server_start
* 函数功能: 套接字线程启动
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
pthread_t sock_server_start(sockets_handle h,int priority)
{
	pthread_attr_t attr;
	struct sched_param param;

	int stack_size;

	SOCK_OBJ *handle = h;

	pthread_attr_init(&attr);
	pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
	pthread_attr_getschedparam(&attr, &param);

	param.sched_priority = priority;
	pthread_attr_setschedparam(&attr, &param); 

	stack_size = handle->tsk_stack_size;
	pthread_attr_setstacksize(&attr, stack_size);

	pthread_create(&handle->tsk_id, &attr, (void *)sock_server_pthread, h);
	RPT(RPT_WRN,"sock start at %d priority",  priority);
	

	return handle->tsk_id;
}

