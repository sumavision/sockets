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
* ��������: NetToTextStr
* ��������: �����ֽ���Ķ�����IP��ַת���� ���ʮ�����ַ���
* �������: AddrFamily: ��ת���ĵ�ַ�����ͣ�IPv4 IPv6
           addr     : �����ֽ���Ķ�����IP��ַ
           NameZize : ���ʮ���Ƶ�ַ�ַ�����С
* �������: AddrName : ָ��ת������ʮ���Ƶ�ַ�ַ�������С��NameZizeָ��
* ���ؽ��: -1:ת��ʧ�ܣ�0:ת���ɹ�
* �޸ļ�¼:
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
* ��������: TextStrToNet
* ��������: ���ʮ�����ַ���ת���ɶ�����IP��ַ�����ֽ���
* �������: 
* �������: 
* ���ؽ��: �ɹ�����1��δ����ʽ��Ϊ��Ч��ַ����0��ָ���ĵ�ַ��δ֪����-1
* �޸ļ�¼:
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
* ��������: sock_print_addr
* ��������: ��ӡIP��ַ��˿ں�
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
* ��������: sock_close
* ��������: �ر��׽���
* �������: 
* �������: ��
* ���ؽ��: ��
* �޸ļ�¼:
******************************************************************************************/
static void sock_close(int socket_fd)
{
	if(socket_fd > 0)
		close(socket_fd);
}
 /*****************************************************************************************
* ��������: sock_create
* ��������: �����׽���
* �������: AddrFamily:��ַ���ͣ���ֵ��ΪSOCK_AF_IPv4��SOCK_AF_IPv6��
           SockType :�׽������ͣ���ֵ��ΪSOCK_UDP_DGRAM��SOCK_TCP_STREAM��
           SockProto :Э�飬��ֵ��ΪSOCK_PROTO_TCP��SOCK_PROTO_UDP��
* �������: ��
* ���ؽ��: �����ɹ������׽��������������򷵻�-1
* �޸ļ�¼:
******************************************************************************************/
static int sock_create(int AddrFamily,int SockType,int SockProto)
{
	int socket_fd = -1;

	socket_fd = socket(AddrFamily,SockType, SockProto);

	return socket_fd;
}
 /*****************************************************************************************
* ��������: sock_bind
* ��������: ���׽������������ַ��
* �������: SockFd : �׽���������
           ServAddr :ָ���������һ����ַ������IP��ַ��˿�
* �������: ��
* ���ؽ��: �󶨳ɹ�����0��ʧ�ܷ���-1
* �޸ļ�¼:
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
* ��������: sock_listen
* ��������: ʵ���������Կͻ�����������
* �������: 
* �������: 
* ���ؽ��: �ɹ� 0��ʧ�� -1
* �޸ļ�¼:
******************************************************************************************/
static int sock_listen(int SockFd)
 {
 	int ret = 0;

	ret = listen(SockFd,MAX_CONNECT_NUM);

	return ret;
 }

/*****************************************************************************************
* ��������: sock_accept
* ��������: ����������󲢽�������
* �������: 
* �������: 
* ���ؽ��: �ɹ������׽�����������ʧ�ܷ���-1
* �޸ļ�¼:
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
* ��������: sock_recv
* ��������: ��������
* �������: SockFd:�׽�����������size:�˴οɽ��յ�����ֽ���; 
           flags:�ı��׽��ֵ��õ�Ĭ����Ϊ��ĳЩ���棬һ��Ϊ0
* �������: buff :ָ��������ݵĴ洢�ռ�
* ���ؽ��: ���ճɹ����ش˴ν��յ����ݴ�С��ʧ�ܷ���-1
* �޸ļ�¼:
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
* ��������: sock_recv_from_clntAddr
* ��������: ��ָ����ַ�Ŀͻ��˽�������
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
* ��������: sock_send
* ��������: ��������
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
* ��������: sock_send_to_clntAddr
* ��������: ���͵�ָ����ַ�Ŀͻ���
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
* ��������: sock_option_set
* ��������: �����׽���ѡ��
* �������: 
* �������: 
* ���ؽ��: �ɹ�����0��������-1
* �޸ļ�¼:
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
* ��������: sock_option_get
* ��������: ��ѯĳ���׽���ѡ��״̬
* �������: 
* �������: 
* ���ؽ��: �ɹ�����0��������-1
* �޸ļ�¼:
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
* ��������: sock_opt_list_set
* ��������: ��ʼ�����׽���ѡ������
* �������: 
* �������: 
* ���ؽ��: �ɹ�����0��������-1
* �޸ļ�¼:
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
* ��������: sock_is_ready
* ��������: �������Ƿ��Ѿ�׼����
* �������: socket_fd:�׽�����������timeout:��ʱ����ʱ��ֵ
* �������: ��
* ���ؽ��: ׼����������������Ŀ����ʱ����0��������-1
* �޸ļ�¼:
******************************************************************************************/
static int sock_is_ready(int socket_fd, uint32_t timeout/*ms*/)
{
	fd_set fdset;

	int ret = 0;
	
	struct timeval timeval;
	memset(&timeval, 0, sizeof(struct timeval));
	timeval.tv_sec = timeout / 1000;
	timeval.tv_usec = (timeout % 1000) * 1000;

	//��fdset����λ����Ϊ0(������״̬����)
	FD_ZERO(&fdset);
	//��socket_fd������λ��1
	FD_SET(socket_fd, &fdset);

	//�������Ƿ�ɶ�
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

	//�����������Ƿ��Ծ�����
	if(FD_ISSET(socket_fd, &fdset) == 0)
	{
		RPT(RPT_ERR, "socket_fd not set");
		return  0;
	}

	return ret;
}
/*****************************************************************************************
* ��������: sock_snd_flag_set
* ��������: �����Ƿ������ɲ�׼�����͵ı�־
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
******************************************************************************************/
void sock_snd_flag_set(sockets_handle h,char state)
{
	SOCK_OBJ *handle = h;
	
	pthread_mutex_lock(&handle->mux);
	handle->sock_snd_flag = state;
	pthread_mutex_unlock(&(handle->mux));
}
/*****************************************************************************************
* ��������: sock_snd_flag_get
* ��������: ��ѯ���������Ƿ���ɵı�־
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
******************************************************************************************/
char sock_snd_flag_get(sockets_handle h)
{
	SOCK_OBJ *handle = h;
	char state = 0;
	
	state = handle->sock_snd_flag ;

	return state;
}
 /*****************************************************************************************
* ��������: sock_addr_list_get
* ��������: ��������ַ�б�Ļ�ȡ������һ�������ͷ�������ӳ�䵽һ����ַ
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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

	//�˿ں��ַ���
	sprintf(PortStr,"%d",SocketParam->port);
	//ip��ַ�ַ�����ʽ
	LocalIPNet = htonl(SocketParam->AddrIP);
	if (NetToTextStr(SocketParam->addr_family,LocalIPNet,LocalAddr,sizeof(LocalAddr)) == -1)
	{
		RPT(RPT_ERR,"AddrIP str get fail");
		return -1;
	}
	//IPv4 IPv6 ������
	HintAddr.ai_family = SOCK_AF_UNSPEC;  
	//�κ�addr/port������
	HintAddr.ai_flags = AI_PASSIVE;          
	HintAddr.ai_socktype = SocketParam->sock_type;
	HintAddr.ai_protocol = SocketParam->protocol;

	RPT(RPT_WRN,"Local addr %d=%d %s/%s",SocketParam->AddrIP,LocalIPNet,LocalAddr,PortStr);

	ret = getaddrinfo(LocalAddr,PortStr,&HintAddr,AddrList);

	return ret;
 }
 /*****************************************************************************************
* ��������: sock_server_init
* ��������: ��Ѱ��ַ�б����ҿ����׽��֣�tcp �׽��ִ��� �� ����
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
	
	//��Ѱ��ַ�б����ҿ����׽��֣�tcp �׽��ִ��� �� ����
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
		//�˴���ʾ��IPv4��Ч
		sock_print_addr(addr->ai_addr,"local addr ");
		//bind listen successful
		break;
	}

	//�ͷ�����ռ�
	freeaddrinfo(List);
	if ( NULL == addr)
	{
		sock_fd = -1;
	}

	return sock_fd;
}
/*****************************************************************************************
* ��������: sock_Id_local_get
* ��������: ��ȡ���ط��������׽���������
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
* ��������: sock_stream_recv_package
* ��������: ���׽��ֽ�������
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
		//�������Ƿ�����
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
* ��������: sock_dgram_recv_package
* ��������: ���ݰ��׽��ֽ�������
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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

	//�ͻ�����ַ��Ϣ��ӡ ������IPv4
	sock_print_addr(ClntAddr,"client addr ");

	/************************* ��ӡ ������Ϣ *****************************/
	ctrl_frame_to_string(pBuff);

	return RecvLen;
}
/*****************************************************************************************
* ��������: sock_server_recv
* ��������: �׽��ֽ�������
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
* ��������: sock_stream_send_package
* ��������: ���׽��ַ�������
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
* ��������: sock_dgram_send_package
* ��������: ���ݰ��׽��ַ�������
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
	//�ͻ�����ַ��Ϣ��ӡ ������IPv4
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
* ��������: sock_server_send
* ��������: ��������
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
* ��������: sock_server_pthread
* ��������: �׽����߳�
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
		//��ȡ�����׽��֣����󶨱��ص�ַ��˿�
		sock_fd = sock_Id_local_get(handle);
		if (sock_fd < 0)
		{
			break;
		}
		else if (0 == sock_fd)
		{
			continue;
		}
		//��ȡ����
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
			
			//�ȴ��˴����ݽ�����Ϻ󣬷��ͷ��ؽ����
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

			//tcp accept ÿ�η��ͽ�����Ӧ�ر��׽��֣�udp����
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
* ��������: sock_opt_struct_val
* ��������: �׽���ѡ���б�
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
			//�׽��ֽ��ջ�������С
			pOpt->flag     = 0x5a;
			pOpt->level    = SOCK_LEVEL_SOCKET;
			pOpt->optName  = SOCK_OPT_RCVBUF;
			pOpt->val      = &(sockInit->RecvBuffLen);
			pOpt->optLen   = sizeof(sockInit->RecvBuffLen);
			strcpy(pOpt->optStr,"opt_RecvBuff");
			break;
		case SOCK_OPT_SNDBUF:
			//�׽��ַ��ͻ�������С
			pOpt->flag     = 0x5a;
			pOpt->level    = SOCK_LEVEL_SOCKET;
			pOpt->optName  = SOCK_OPT_SNDBUF;
			pOpt->val      = &(sockInit->SndBuffLen);
			pOpt->optLen   = sizeof(sockInit->SndBuffLen);
			strcpy(pOpt->optStr,"opt_SndBuff"); 
			break;
		case SOCK_OPT_REUSEADDR:
			//�׽��� bind ��ַ����
			pOpt->flag     = 0x5a;
			pOpt->level    = SOCK_LEVEL_SOCKET;
			pOpt->optName  = SOCK_OPT_REUSEADDR;
			pOpt->optState 	= 1;
			pOpt->val      = &(pOpt->optState);
			pOpt->optLen   = sizeof(pOpt->optState);
			strcpy(pOpt->optStr,"opt_ReUse_Addr"); 
			break;
		case SOCK_OPT_BROADCAST:
			//�׽��� ����㲥
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
* ��������: sock_opt_list_init
* ��������: �׽���ѡ���б�
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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
* ��������: sock_server_create
* ��������: �׽��ַ������Ĵ���,�ṹ��ռ���䣬������������
* �������: 
* �������: 
* ���ؽ��: ����ָ���׽��ֽṹ��ľ��
* �޸ļ�¼:
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

	//��ʼ�����շ���buff
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

	//sock ��������
	if (SockInit == NULL)
	{
		handle->params = sock_params_default;
	}
	else 
	{
		handle->params = SockInit->params;
	}

	handle->tsk_stack_size = SOCK_TSK_STACK_SIZE;

	//sock �߳̿��Ʋ�������
	handle->sock_connect_ctrl = true;
	handle->sock_recv_ctrl  = true;
	handle->sock_snd_flag   = true;
	handle->exit_ctrl       = true;

	handle->sock_recv_snd   = SockInit->sock_recv_snd;

	//�׽���ѡ��
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
* ��������: sock_server_delete
* ��������: �׽����̹߳ر�
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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

	//�ȴ��߳̽���
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
* ��������: sock_server_start
* ��������: �׽����߳�����
* �������: 
* �������: 
* ���ؽ��: 
* �޸ļ�¼:
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

