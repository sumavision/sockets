#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "../../../../proj9550A/app/suma_demos/core/link_layer_public.h"
#ifdef PARAM_MQ_CTRL
#include "/opt/cmai/include/param_mq/param_mq.h"
#else 
#include "../../param_mq/param_mq.h"
#endif
#include "../../suma_api/suma_api.h"

#include "app_udp.h"
/****************************************************************************************
 *                         static
 ****************************************************************************************/
static int rpt_lvl = 2; /* report level: ERR, WRN, INF, DBG */

#ifdef PARAM_MQ_CTRL
static param_mq_handle glb_udp_snd;
static param_mq_handle glb_udp_recv;
#endif


const CF_PARAM_OBJ cf_sys_param_table[] =
{
    {CF_SYS_REBOOT, IF_SYS_REBOOT, PARAM_UINT8_TYPE, 0, 1, CF_WRITE_ONLY},
    {CF_NET_IPADDR_DATA, IF_NET_IPADDR_DATA, PARAM_IP_TYPE, 0, 0, CF_READ_WRITE}, //confirmed
    {CF_NET_MASK_DATA, IF_NET_MASK_DATA, PARAM_IP_TYPE, 0, 0, CF_READ_WRITE}, //confirmed
    {CF_NET_GATE_DATA, IF_NET_GATE_DATA, PARAM_IP_TYPE, 0, 0, CF_READ_WRITE}, //confirmed
    {CF_DEFAULT_PARAM, 0, PARAM_UINT8_TYPE, 0, 0, CF_READ_WRITE},
    {CF_SYS_SNMP_IP, IF_SYS_SNMP_IP, PARAM_IP_TYPE, 0, 0,CF_READ_WRITE},
    {CF_SYS_UART_RATE, IF_SYS_UART_RATE, PARAM_UINT8_TYPE, 0, 6, CF_READ_WRITE},
    {CF_SYS_SERIAL_ADDR, IF_SYS_ID, PARAM_HEX_TYPE, 1, 65535, CF_READ_WRITE},
	{CF_SYS_SOFT_VER, IF_SYS_SOFT_VER2, PARAM_STRING_TYPE, 0, 0, CF_READ_ONLY}, //confirmed
	{CF_SYS_HARD_VER, IF_SYS_HARD_VER, PARAM_STRING_TYPE, 0, 0, CF_READ_ONLY}, //confirmed
    {CF_SYS_PARAM_SN, IF_SYS_PARAM_SN, PARAM_STRING_TYPE, 0, 0, CF_READ_ONLY}, //confirmed
};

const CF_PARAM_OBJ cf_videnc_param_table[] =
{
    {CF_VIDENC_INPUT, IF_VID_ENC_INPUT, PARAM_UINT8_TYPE, 0, 5, CF_READ_WRITE},
    {CF_VIDENC_SYSRATE, IF_SND_SYSRATE, PARAM_INT32_TYPE, 0, 10000, CF_READ_WRITE},
    {CF_VIDENC_ENC_STD, IF_VID_ENC_STD, PARAM_INT32_TYPE, 0, 0xffff, CF_READ_WRITE},
    {CF_VIDENC_SND_MEDIA_MODE, IF_SND_MEDIA_MODE, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
    {CF_VIDENC_BITRATE, IF_VID_ENC_BITRATE, PARAM_INT32_TYPE, 0, 4000, CF_READ_WRITE},
    {CF_VIDENC_WIDTH, IF_ENC_STATUS_ENC_WIDTH, PARAM_INT32_TYPE, 0, 0xffff, CF_READ_ONLY},
    {CF_VIDENC_HEIGHT, IF_ENC_STATUS_ENC_HEIGHT, PARAM_INT32_TYPE, 0, 0xffff, CF_READ_ONLY},
    {CF_VIDENC_ENC_FPS1, IF_VID_ENC_FPS1, PARAM_UINT32_TYPE, 0, 60, CF_READ_WRITE},
    {CF_VIDENC_STATUS_STD, IF_ENC_STATUS_STD, PARAM_UINT32_TYPE, 0, 0xffff, CF_READ_ONLY},
    {CF_VIDENC_FORMATE, IF_VID_ENC_FORMAT, PARAM_UINT32_TYPE, ET_H265, ET_TILE_DEC, CF_READ_WRITE},
    {CF_VIDENC_RESO, IF_VID_ENC_ABSOLUE_RESO, PARAM_UINT32_TYPE, ABSOLUTE_RESO_1080, ABSOLUTE_RESO_D1, CF_READ_WRITE},
};

const CF_PARAM_OBJ cf_audenc_param_table[] =
{
    {CF_AUDENC_CTL, IF_AUD_ENC_CTL, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
    {CF_AUDENC_FORMAT, IF_AUD_ENC_CODEC, PARAM_UINT8_TYPE, 0, 4, CF_READ_WRITE},
    {CF_AUDENC_G711LAW, IF_AUD_ENC_G711_COMPAND, PARAM_UINT8_TYPE, 1, 2, CF_READ_WRITE},
    {CF_AUDENC_VOLUME, IF_AUD_ENC_VOLUME, PARAM_INT32_TYPE, -24, 24, CF_READ_WRITE},
};

const CF_PARAM_OBJ cf_osdenc_param_table[] =
{
    {CF_OSDENC_CTL, IF_VID_ENC_OSD_CTL, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
    {CF_OSDENC_X, IF_VID_ENC_OSD_X, PARAM_UINT8_TYPE, 0, 100, CF_READ_WRITE},
    {CF_OSDENC_Y, IF_VID_ENC_OSD_Y, PARAM_UINT8_TYPE, 0, 100, CF_READ_WRITE},
	{CF_OSDENC_COLOR, IF_VID_ENC_OSD_COLOR, PARAM_UINT8_TYPE, 0, 8, CF_READ_WRITE},
    {CF_OSDENC_COLOR_EDGE, IF_VID_ENC_OSD_COLOR_EDGE, PARAM_UINT8_TYPE, 0, 9, CF_READ_WRITE},
    {CF_OSDENC_SIZE, IF_VID_ENC_OSD_SIZE, PARAM_UINT8_TYPE, 0, 2, CF_READ_WRITE},
    {CF_OSDENC_STR, IF_VID_ENC_OSD_STR, PARAM_STRING_TYPE, 1, 16, CF_READ_WRITE},
};

const CF_PARAM_OBJ cf_recv_param_table[] =
{
    {CF_RECV_CTL, IF_RECV_CTL, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
    {CF_RECV_MULTIMODE, IF_RECV_IP_CASTMODE, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
    {CF_RECV_MULTIADDR, IF_RECV_MULTICAST_ADDR, PARAM_IP_TYPE, 0, 1, CF_READ_WRITE},
    {CF_RECV_PORT, IF_RECV_PORT, PARAM_UINT32_TYPE, 1026, 65530, CF_READ_WRITE},
    {CF_RECV_SYNCMODE, IF_RECV_SYN, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},//现在同步模式只有PCR同步
};

const CF_PARAM_OBJ cf_auddec_param_table[] =
{
    {CF_AUDDEC_CTL, IF_ADEC_CTL, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
    {CF_AUDDEC_CODEC, IF_ADEC_CODEC_TYPE, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
    {CF_AUDDEC_G711LAW, IF_ADEC_COMPANDING_LAW, PARAM_UINT8_TYPE, 1, 2, CF_READ_WRITE},   
    {CF_AUDDEC_GAIN, IF_ADEC_MANGIFY, PARAM_INT8_TYPE, -24, 24, CF_READ_WRITE}, 
};

const CF_PARAM_OBJ cf_osddec_param_table[] =
{
    {CF_OSDDEC_CTL, IF_VDEC_OSD_CTL, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
    {CF_OSDDEC_X, IF_VDEC_OSD_X, PARAM_UINT8_TYPE, 0, 100, CF_READ_WRITE},
    {CF_OSDDEC_Y, IF_VDEC_OSD_Y, PARAM_UINT8_TYPE, 0, 100, CF_READ_WRITE},
    {CF_OSDDEC_COLOR, IF_VDEC_OSD_COLOR, PARAM_UINT8_TYPE, 0, 8, CF_READ_WRITE},
    {CF_OSDDEC_COLOR_EDGE, IF_VDEC_OSD_COLOR_EDGE, PARAM_UINT8_TYPE, 0, 9, CF_READ_WRITE},
};

const CF_PARAM_OBJ cf_snd_param_table[] =
{
    {CF_SND_CTL, IF_SND_CTL, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
    {CF_SND_ADDR, IF_SND_ADDR, PARAM_IP_TYPE, 0, 0, CF_READ_WRITE},
    {CF_SND_PORT, IF_SND_PORT, PARAM_UINT32_TYPE, 1026, 65530, CF_READ_WRITE},
    {CF_SND_TOS, IF_SND_TOS, PARAM_UINT8_TYPE, 0, 255, CF_READ_WRITE},
    {CF_SND_VBV, IF_SND_VBV_FLG, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
    {CF_SND_NO_DECODE_NOSND, IF_SND_NO_DECODE_NO_SND, PARAM_UINT8_TYPE, 0, 1, CF_READ_WRITE},
};

const CF_PARAM_OBJ cf_status_param_table[] =
{
    {CF_STATUS_VIDENC_RATE, IF_ENC_STATUS_VIDBITRATE, PARAM_UINT32_TYPE, 0, 1, CF_READ_ONLY},
    {CF_STATUS_AUDENC_RATE, IF_ENC_STATUS_AUDBITRATE, PARAM_UINT32_TYPE, 0, 0, CF_READ_ONLY},
    {CF_STATUS_VIDDEC_LOST, IF_DEC_STATUS_VID_DISCONTINUE_NUM, PARAM_UINT32_TYPE, 0, 0, CF_READ_ONLY},
    {CF_STATUS_VIDDEC_RATE, IF_DEC_STATUS_VID_BITRATE, PARAM_UINT32_TYPE, 0, 0, CF_READ_ONLY},
    {CF_STATUS_AUDDEC_LOST, IF_DEC_STATUS_AUD_DISCONTINUE_NUM, PARAM_UINT32_TYPE, 0, 1, CF_READ_ONLY},
    {CF_STATUS_AUDDEC_RATE, IF_DEC_STATUS_AUD_BITRATE, PARAM_UINT32_TYPE, 0, 1, CF_READ_ONLY},
};

const CF_PARAM_OBJ cf_combine_param_table[] =
{
    {CF_COMBINE_PARAM_ID, CF_COMBINE_PARAM, PARAM_COMBINE_TYPE, 0, 127, CF_READ_WRITE},
};

const COMBINE_PARAM_OBJ cf_combine_params[] =
{
    {IF_NET_IPADDR_DATA, 4, PARAM_IP_TYPE, 0, 0},
    {IF_NET_MASK_DATA, 4, PARAM_IP_TYPE, 0, 0},
    {IF_NET_GATE_DATA, 4, PARAM_IP_TYPE, 0, 0},
 //   {IF_VID_ENC_INPUT, 1, UINT8_TYPE,  0, 5 },
    {IF_VID_ENC_ABSOLUE_RESO, 1, PARAM_UINT8_TYPE,  ABSOLUTE_RESO_1080, ABSOLUTE_RESO_D1},
   /// {IF_VID_ENC_FORMAT, 1, UINT8_TYPE, ET_H265, ET_TILE_DEC},
    {IF_SND_V35MODE, 1, PARAM_UINT8_TYPE, 0, 0},
    {IF_SND_CTL, 1, PARAM_UINT8_TYPE, 0x0, 0x1},
    {IF_SND_ADDR, 4, PARAM_IP_TYPE, 0, 0},
    {IF_SND_PORT, 4, PARAM_UINT32_TYPE, 1026, 65530},
    {IF_SND_SYSRATE, 4, PARAM_UINT32_TYPE, 100, 4500},
    {IF_RECV_CTL, 1, PARAM_UINT8_TYPE, 0x0, 0x3},
    {IF_RECV_IP_CASTMODE, 1, PARAM_UINT8_TYPE, 0x0, 0x1},
    {IF_RECV_MULTICAST_ADDR, 4, PARAM_IP_TYPE, 0, 0},
    {IF_RECV_PORT, 4, PARAM_UINT32_TYPE, 1026, 65530},
   // {IF_SND_NO_DECODE_NO_SND, 1, UINT8_TYPE, 0, 1},
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

#define UDP_TSK_STACK_SIZE 10*1024
/****************************************************************************************
 *                        Function
 ****************************************************************************************/
/*****************************************************************************************
* 函数名称: udp_sock_opt_list
* 函数功能: 套接字选项添加
* 输入参数: 
* 输出参数: 
* 返回结果: 套接字选项添加数目
* 修改记录:
******************************************************************************************/
static int udp_sock_opt_list(SOCK_INIT *sockInit)
{
	int num = 0;

	sockInit->OptList[num] = SOCK_OPT_RCVBUF;
	num++;

	sockInit->OptList[num] = SOCK_OPT_SNDBUF;
	num++;

	sockInit->OptList[num] = SOCK_OPT_REUSEADDR;
	num++;

	sockInit->OptList[num] = SOCK_OPT_BROADCAST;
	num++;

	return num;
}
 /*****************************************************************************************
* 函数名称: udp_param_get_from_mq
* 函数功能: 通过消息队列查询参数
* 输入参数: param_id: 参数索引
* 输出参数: buf:指向查询结果
* 返回结果: 查询是否成功；-1查询失败否则成功
* 修改记录:
******************************************************************************************/
static int  udp_param_get_from_mq(int param_id,char *buf)
 {
	int ret = 0;
	msg_params msg_q;

	if(buf == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}
#ifdef PARAM_MQ_CTRL
	msg_q.src_id = PARAM_MQ_ID_UDP;
	msg_q.dst_id = PARAM_MQ_ID_PROCESS;
	msg_q.param_id = param_id;
	msg_q.wr_flg = MSG_Q_FLAG_READ;
	msg_q.data_len = 2;
	ret = param_mq_send(glb_udp_snd, &msg_q,  18);
	ret =  param_mq_receive(glb_udp_recv, &msg_q);
	if (ret < 0)
	{
		return -1;
	}

	//strncpy(buf,msg_q.data,len);
	strcpy(buf,msg_q.data);

	RPT(RPT_DBG,"recv msg(%d) src : %d id :%d  %s",ret,msg_q.src_id,msg_q.param_id,msg_q.data);
#endif
	return ret;
 }
 /*****************************************************************************************
* 函数名称: udp_param_set_by_mq
* 函数功能: 通过消息队列设置参数
* 输入参数: param_id:参数索引；buf:指向具体的配置值
* 输出参数: 无
* 返回结果: 设置是否成功；
* 修改记录:
******************************************************************************************/
static int  udp_param_set_by_mq(int param_id,char *buf)
 {
	int ret = CF_SET_OK;

	msg_params msg_q;

	if(buf == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return CF_SET_ERROR;
	}
#ifdef PARAM_MQ_CTRL
	msg_q.src_id = PARAM_MQ_ID_UDP;
	msg_q.dst_id = PARAM_MQ_ID_PROCESS;
	msg_q.param_id =param_id;
	msg_q.wr_flg = MSG_Q_FLAG_WRITE;

	strncpy(msg_q.data,buf,MAX_PARAM_MQ_LEN);
	msg_q.data_len = strlen(msg_q.data) + 1;
	ret = param_mq_send(glb_udp_snd, &msg_q,  18);

	if (ret < 0)
	{
		ret = CF_SET_ERROR;
	}
	ret = CF_SET_OK;

	RPT(RPT_DBG,"recv msg(%d) src : %d id :%d  %s",ret,msg_q.src_id,msg_q.param_id,msg_q.data);
#endif
	return ret;
 }

 /*****************************************************************************************
* 函数名称: udp_device_id_get
* 函数功能: 获取设备ID
* 输入参数: 无
* 输出参数: 无
* 返回结果: 设备ID值
* 修改记录:
******************************************************************************************/
static int udp_device_id_get(void)
 {
	int id = 0;
	char buff[10] = {0};
	udp_param_get_from_mq(IF_SYS_ID,buff);

	RPT(RPT_WRN,"udp local device id = %s",buff);

	id = (int)strtoul(buff, 0, 16);

	return id;
 }
/*****************************************************************************************
* 函数名称: udp_msg_reply
* 函数功能: 对解析结果以及设置或查询结果的处理，用于应答消息
* 输入参数: type:解析/设置/查询结果类型
* 输出参数: SndCF: 指向发送应答消息的帧结构；
           此处对帧结构中的数据字段以及命令/应答字段进行配置
* 返回结果: 无
* 修改记录:
******************************************************************************************/
static void udp_msg_reply(int type,CTRL_FRAME *SndCF)
{
	if(SndCF == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return;
	}
	
	char *buff = SndCF->ctrl_data;
	
	switch (type)
	{
		case CF_SET_OK:
			strncpy(buff,"OK",2);
			SndCF->ctrl_order_ack = FRAME_ACK_VAL;
			break;
		case CF_SET_ERROR:
			strncpy(buff,"ERR",3);
			SndCF->ctrl_order_ack = FRAME_ACK_VAL;
			break;
		case CF_CMD_OK:
			SndCF->ctrl_order_ack = FRAME_ACK_VAL;
			break;
		case CF_CMD_ERROR:
			SndCF->ctrl_order_ack = FRAME_ERROR_VAL;
			break;
		default :
			RPT(RPT_ERR,"udp_msg_reply type not exit");
			break;
	}
}
/*****************************************************************************************
* 函数名称: ctrl_frame_to_string
* 函数功能: 打印控制帧结构数据
* 输入参数: CFBuff:指向所需打印的控制帧
* 输出参数: 无
* 返回结果: 无
* 修改记录:
******************************************************************************************/
void ctrl_frame_to_string(char *CFBuff)
{
	int Anl_Len = 0;
	int i = 0;
	char buff[100] = {0};

	if(CFBuff == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return;
	}
	
	char ctrl_star = *((char*)CFBuff + Anl_Len);
	sprintf(buff + Anl_Len*2,"%02x",ctrl_star);
	Anl_Len += 1;
	
	unsigned short ctrl_dev_id = *((unsigned short*)(CFBuff+Anl_Len));
	//ctrl_dev_id = htons(ctrl_dev_id);
	sprintf(buff + Anl_Len*2,"%04x",ctrl_dev_id);
	Anl_Len += 2;
	
	char ctrl_order_ack = *((char*)(CFBuff+Anl_Len));
	sprintf(buff + Anl_Len*2,"%02x",ctrl_order_ack);
	Anl_Len += 1;
	
	char ctrl_set_get = *((char*)(CFBuff+Anl_Len));
	sprintf(buff + Anl_Len*2,"%02x",ctrl_set_get);
	Anl_Len += 1;
	
	unsigned int ctrl_id =  *((unsigned int*)(CFBuff+Anl_Len));
	//ctrl_id = htons(ctrl_id);
	sprintf(buff + Anl_Len*2,"%08x",ctrl_id);
	Anl_Len += 4;
	
	char ctrl_data[FRAME_DATA_LEN];
	memcpy(ctrl_data,(CFBuff+Anl_Len),FRAME_DATA_LEN);
	for (i = 0;i< FRAME_DATA_LEN;i++)
	{
		sprintf(buff+Anl_Len*2+i*2,"%02X",(unsigned char)ctrl_data[i]);
	}
	Anl_Len += FRAME_DATA_LEN;
	
	char ctrl_check = *((char*)(CFBuff+Anl_Len));
	sprintf(buff + Anl_Len*2,"%02x",ctrl_check);
	Anl_Len += 1;
	
	char ctrl_end = *((char*)(CFBuff+Anl_Len));
	sprintf(buff + Anl_Len*2,"%02x",ctrl_end);
	Anl_Len += 1;

	RPT(RPT_WRN,"contral frame: %s",buff);
}
/*****************************************************************************************
* 函数名称: udp_send_to_sock
* 函数功能: 将应答控制帧数据传到 sock线程，发送给客户端
* 输入参数: 
* 输出参数: 无
* 返回结果: 无
* 修改记录:
******************************************************************************************/
static void udp_send_to_sock(UDP_OBJ *UdpObj)
{
	CTRL_FRAME SndCF;
	CTRL_FRAME* UdpCF = NULL;
	SOCK_BUFF_OBJ *pSockBuff = NULL;
	char *pSndBuff          = NULL;
	unsigned char *pByteSndCF        = NULL;

	int SndDataSize = 0;
	int SndBuffSize = 0;
	int Anl_Len   = 0;
	int i = 0;

	unsigned char TCheck = 0;
	unsigned int CheckVal = 0;

	if(UdpObj == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return;
	}

	pSockBuff     = UdpObj->udp_sock_buff;
	pSndBuff      = (char*)pSockBuff->SndBuff;
	SndBuffSize   = pSockBuff->SndBuffLen;
	SndDataSize   = pSockBuff->SndDataLen;

	//sock snd buff已满不做处理
	if (SndDataSize > SndBuffSize)
	{
		RPT(RPT_ERR,"sock snd buff filled");
		return;
	}
	
	memset((char*)&SndCF,0,sizeof(CTRL_FRAME));
	UdpCF = &(UdpObj->UdpCF);

	//应答帧 
	SndCF.ctrl_start = FRAME_START_VAL;

	SndCF.ctrl_dev_id = htons(UdpObj->local_dev_id);

	udp_msg_reply(UdpObj->flags, &SndCF);
	//RPT(RPT_WRN,"ctrl_data = %s",SndCF.ctrl_data);

	//错误帧 此处字段 不需处理
	if (SndCF.ctrl_order_ack != FRAME_ERROR_VAL)
	{
		SndCF.ctrl_id   = htonl(UdpCF->ctrl_id);
		//SndCF.ctrl_id   =  (UdpCF->ctrl_id);
		SndCF.ctrl_set_get = UdpCF->ctrl_set_get;
		if (SndCF.ctrl_set_get == FRAME_GET_VAL)
		{
			memcpy(SndCF.ctrl_data,UdpCF->ctrl_data,FRAME_DATA_LEN);
		}

		//校验码计算
		pByteSndCF = (unsigned char*)(&SndCF);
		//防止字节对齐问题，此处用 sizeof (CTRL_FRAME)
		for (i = 0;i < sizeof (CTRL_FRAME) - FRAME_CHECK_LEN - FRAME_END_LEN;i++)
		{
			TCheck = pByteSndCF[i];
			CheckVal += TCheck;
			//RPT(RPT_WRN,"CTRL_FRAME(size) = %d,TCheck = 0x%X,CheckVal = 0x%X",sizeof (CTRL_FRAME),TCheck,CheckVal);
		}
		SndCF.ctrl_check = (char)(CheckVal&0xff);
	}
	SndCF.ctrl_end  =  FRAME_END_VAL;
	
	//传给sock snd buff
	//memcpy(pSndBuff,(char*)&SndCF,CTRL_FRAME_LEN);
	//字节对齐导致不能 复制
	pSndBuff += SndDataSize;
	Anl_Len = 0;
	pSndBuff[Anl_Len] = SndCF.ctrl_start;
	Anl_Len++;
	
	//设备ID 大端传输
	pSndBuff[Anl_Len] = SndCF.ctrl_dev_id>>8;
	Anl_Len++;
	pSndBuff[Anl_Len] = SndCF.ctrl_dev_id&0xff;
	Anl_Len++;

	pSndBuff[Anl_Len] = SndCF.ctrl_order_ack;
	Anl_Len++;

	pSndBuff[Anl_Len] = SndCF.ctrl_set_get;
	Anl_Len++;

	//参数ID 大端传输
	pSndBuff[Anl_Len] = SndCF.ctrl_id>>24;
	Anl_Len++;
	pSndBuff[Anl_Len] = (SndCF.ctrl_id>>16)&0xff;
	Anl_Len++;
	pSndBuff[Anl_Len] = (SndCF.ctrl_id>>8)&0xff;
	Anl_Len++;
	pSndBuff[Anl_Len] = SndCF.ctrl_id&0xff;
	Anl_Len++;

	memcpy((pSndBuff+Anl_Len),SndCF.ctrl_data,FRAME_DATA_LEN);
	Anl_Len += FRAME_DATA_LEN;

	pSndBuff[Anl_Len] = SndCF.ctrl_check;
	Anl_Len++;

	pSndBuff[Anl_Len] = SndCF.ctrl_end;
	Anl_Len++;
	
	pSockBuff->SndDataLen += Anl_Len;

	/********************** 打印 发送数据 *********************************/
	//ctrl_frame_to_string(pSndBuff);
}
/*****************************************************************************************
* 函数名称: cf_convert_msg_to_demo
* 函数功能: 控制帧数据字段 格式 由 二进制数据 转化为 字符串
* 输入参数: srcBuff:转化前的数据存放空间
* 输出参数: destBuf:转化后的数据存放空间
* 返回结果: 转化是否成功
* 修改记录:
******************************************************************************************/
static int cf_convert_msg_to_demo(char *destBuf, char *srcBuff, int type,
                                                   int max_value,int min_value)
{
    uint8_t *msg_buf = (uint8_t*)srcBuff;
	uint8_t val_uint8 = 0;
	int8_t val_int8 = 0;
	uint32_t val_uint32 = 0;
	int32_t val_int32 = 0;
	
	if ((NULL == destBuf)|| (NULL == srcBuff))
	{
	    RPT(RPT_ERR,"cf_set_data_type_change pointer NULL error!\n");
        return CF_SET_ERROR;
	}
	
    switch (type)
	{
	    case PARAM_IP_TYPE:
	        snprintf(destBuf,MAX_PARAM_LEN, "%d.%d.%d.%d", msg_buf[0], msg_buf[1], msg_buf[2], msg_buf[3]);
	        break;
		case PARAM_UINT8_TYPE:
	        val_uint8 = (uint8_t)msg_buf[0];
			
	        if ((val_uint8 > (uint8_t)max_value) ||(val_uint8 < (uint8_t)min_value))
	        {
				RPT(RPT_ERR,"cf_set_data_type_change(type = UINT8_TYPE) param(= %u) out of range[%u, %u]!\n",
					(uint16_t)val_uint8, (uint16_t)min_value, (uint16_t)max_value);				
				return CF_SET_ERROR;
			}	    
	        snprintf(destBuf,MAX_PARAM_LEN, "%u", val_uint8);
	        break;            
		case PARAM_INT8_TYPE:
			val_int8 = (int8_t)msg_buf[0];

			if ((val_int8 > (int8_t)max_value) ||(val_int8 < (int8_t)min_value))
			{
				RPT(RPT_ERR,"cf_set_data_type_change(type = INT8_TYPE) param(= %d) out of range[%d, %d]!\n",
					(int16_t)val_int8, (int16_t)min_value, (int16_t)max_value);				
				return CF_SET_ERROR;
			}		
			snprintf(destBuf,MAX_PARAM_LEN, "%d", val_int8);
			break;
        case PARAM_XHEX_TYPE:  
            val_uint32 = (uint32_t)(msg_buf[0] | (msg_buf[1]<<8) |
                                         (msg_buf[2]<<16) | (msg_buf[3]<<24));
                    
            if ((val_uint32 > (uint32_t)max_value) ||(val_uint32 < (uint32_t)min_value))
            {
                  RPT(RPT_ERR,"cf_set_data_type_change(type = UINT32_TYPE) param(= %u) out of range[%u, %u]!\n",
                      val_uint32, (uint32_t)min_value, (uint32_t)max_value);                        
                  return CF_SET_ERROR;
            }
            snprintf(destBuf, MAX_PARAM_LEN, "0x%x", val_uint32);
            break;
        case PARAM_HEX_TYPE: 
            val_uint32 = (uint32_t)(msg_buf[0] | (msg_buf[1]<<8) |
                                         (msg_buf[2]<<16) | (msg_buf[3]<<24));
                    
            if ((val_uint32 > (uint32_t)max_value) ||(val_uint32 < (uint32_t)min_value))
            {
                     RPT(RPT_ERR,"cf_set_data_type_change(type = UINT32_TYPE) param(= %u) out of range[%u, %u]!\n",
                              val_uint32, (uint32_t)min_value, (uint32_t)max_value);                        
                     return CF_SET_ERROR;
            }
            snprintf(destBuf, MAX_PARAM_LEN, "%x", val_uint32);
            break;  
         case PARAM_UINT16_TYPE:
		    val_uint32 = (uint32_t)(msg_buf[0] | msg_buf[1]<<8);
			if ((val_uint32 > (uint32_t)max_value) || (val_uint32 < (uint32_t)min_value))
			{
				RPT(RPT_ERR,"cf_set_data_type_change(type = UINT32_TYPE) param(= %u) out of range[%u, %u]!\n",
					val_uint32, (uint32_t)min_value, (uint32_t)max_value);				
				return CF_SET_ERROR;
			}
			snprintf(destBuf, MAX_PARAM_LEN, "%u", val_uint32);
            break;
		case PARAM_UINT32_TYPE:
		    val_uint32 = (uint32_t)(msg_buf[0] | (msg_buf[1]<<8) |
			                     (msg_buf[2]<<16) | (msg_buf[3]<<24));
			
			if ((val_uint32 > (uint32_t)max_value) ||(val_uint32 < (uint32_t)min_value))
			{
				RPT(RPT_ERR,"cf_set_data_type_change(type = UINT32_TYPE) param(= %u) out of range[%u, %u]!\n",
					val_uint32, (uint32_t)min_value, (uint32_t)max_value);				
				return CF_SET_ERROR;
			}
			snprintf(destBuf, MAX_PARAM_LEN, "%u", val_uint32);
			break;  
        case PARAM_INT16_TYPE:
			val_int32 = (int32_t)(msg_buf[0] | msg_buf[1]<<8);
			if ((val_int32 > max_value) ||(val_int32 < min_value))
			{
				RPT(RPT_ERR,"cf_set_data_type_change(type = INT32_TYPE) param(= %d) out of range[%d, %d]!\n",
					val_int32, min_value, max_value);				
				return CF_SET_ERROR;
			}
			
			snprintf(destBuf,MAX_PARAM_LEN, "%d", val_int32);
			break;  
		case PARAM_INT32_TYPE:
			val_int32 = (int32_t)(msg_buf[0] | (msg_buf[1]<<8) | 
				               (msg_buf[2]<<16) | (msg_buf[3]<<24));
			
			if ((val_int32 > max_value) ||(val_int32 < min_value))
			{
				RPT(RPT_ERR,"cf_set_data_type_change(type = INT32_TYPE) param(= %d) out of range[%d, %d]!\n",
					val_int32, min_value, max_value);				
				return CF_SET_ERROR;
			}
			
			snprintf(destBuf,MAX_PARAM_LEN, "%d", val_int32);
			break;            
		case PARAM_STRING_TYPE:
			if (strlen((char *)msg_buf) > max_value)
			{
				RPT(RPT_ERR,"cf_set_data_type_change(type = STRING_TYPE) param(string) out of range[, %u]!\n",
					(uint16_t)max_value);				
				return CF_SET_ERROR;
			}

			memcpy(destBuf, msg_buf, FRAME_DATA_LEN);
		    destBuf[FRAME_DATA_LEN] = '\0';
			break;            
        case PARAM_COMBINE_TYPE:
			memcpy(destBuf, msg_buf, FRAME_DATA_LEN);
            break;            
		default:
		    RPT(RPT_ERR,"cf_set_data_type_change param's type(= %u) is unknow!\n", type);
		    return CF_SET_ERROR;
	}

	return CF_SET_OK;
}
/*****************************************************************************************
* 函数名称: cf_convert_msg_from_demo
* 函数功能: 获取二进制 控制帧数据字段；由字符串转化
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int cf_convert_msg_from_demo(char *destBuf, char *srcBuff, int type)
{
    uint8_t *msg_buf = (uint8_t*)destBuf;
	uint32_t var_uint32 = 0;
	int32_t var_int32 = 0;
    char * c1 = srcBuff;
    uint32_t val;
    char c;
   
	if ((NULL == destBuf) || (NULL == srcBuff))
	{
		RPT(RPT_ERR,"cf_get_data_type_change pointer NULL error!\n");		  
		return -1;
	}

    switch (type)
	{
        case PARAM_IP_TYPE:
               sscanf(srcBuff, "%d.%d.%d.%d", (int *)&msg_buf[0], 
					   (int *)&msg_buf[1], (int *)&msg_buf[2], (int *)&msg_buf[3]);
               break;
		case PARAM_STRING_TYPE:
               srcBuff[FRAME_DATA_LEN - 1] = '\0';
               strcpy((char *)msg_buf, (char *)srcBuff);
               msg_buf[FRAME_DATA_LEN - 1] = (uint8_t)'\0'; /*lint warning modified*/
               break;
		case PARAM_UINT8_TYPE:
               msg_buf[0] = (uint8_t)(atoi(srcBuff) & 0xff);
               break;
		case PARAM_INT8_TYPE:
               msg_buf[0] = (int8_t)(atoi(srcBuff) & 0xff);
               break;
		case PARAM_UINT32_TYPE:
               var_uint32 = (uint32_t)atoi(srcBuff);
               msg_buf[0] = (uint8_t)(var_uint32 & 0xff); /*lint warning modified*/
               msg_buf[1] = (uint8_t)((var_uint32 >> 8)&0xff);
			   msg_buf[2] = (uint8_t)((var_uint32 >> 16)&0xff);
               msg_buf[3] = (uint8_t)((var_uint32 >> 24)&0xff);
               break;
		case PARAM_INT32_TYPE:
               var_int32 = (int32_t)atoi(srcBuff);
               msg_buf[0] = (uint8_t)(var_int32 & 0xff);
               msg_buf[1] = (uint8_t)((var_int32 >> 8)&0xff);
			   msg_buf[2] = (uint8_t)((var_int32 >> 16)&0xff);
               msg_buf[3] = (uint8_t)((var_int32 >> 24)&0xff);
                break;
         case PARAM_INT16_TYPE:
         case PARAM_UINT16_TYPE:
               var_int32 = (int32_t)atoi(srcBuff);
               msg_buf[0] = (uint8_t)(var_int32 & 0xff);
               msg_buf[1] = (uint8_t)((var_int32 >> 8)&0xff);
               break;
         case PARAM_XHEX_TYPE:  //相关PID使用
               c = * c1;
               val = 0;
               while(c != '\0') 
               {
                  if ((c >= '0')&&(c <= '9')) 
                  {
                      val = (val * 16) + (c - '0');
                      c = *(++c1);
                  } 
                  else if ((c >= 'A')&&(c <= 'F')) 
                  {
                      val = (val << 4) | (c + 10 - 'A');
                      c = *(++c1);
                  } 
                  else if ((c >= 'a')&&(c <= 'f')) 
                  {
                      val = (val << 4) | (c + 10 - 'a');
                      c = *(++c1);
                  }
               }
               var_uint32 = val;
               msg_buf[0] = var_uint32&0xff;
               msg_buf[1] = (var_uint32 >> 8)&0xff;
               msg_buf[2] = (var_uint32 >> 16)&0xff;
               msg_buf[3] = (var_uint32 >> 24)&0xff;
               RPT(RPT_WRN,"uint32:%u",var_uint32);
               break;               
          case PARAM_HEX_TYPE:   //只有串口地址使用
                c = * c1;
                val = 0;
                while(c != '\0') 
                {
                   if ((c >= '0')&&(c <= '9')) 
                   {
                      val = (val * 16) + (c - '0');
                      c = *(++c1);
                   } 
                   else if ((c >= 'A')&&(c <= 'F')) 
                   {
                      val = (val << 4) | (c + 10 - 'A');
                      c = *(++c1);
                   } 
                   else if ((c >= 'a')&&(c <= 'f')) 
                   {
                      val = (val << 4) | (c + 10 - 'a');
                      c = *(++c1);
                   }
                }
                var_uint32 = val;
                msg_buf[0] = var_uint32&0xff;
                msg_buf[1] = (var_uint32 >> 8)&0xff;
                msg_buf[2] = (var_uint32 >> 16)&0xff;
                msg_buf[3] = (var_uint32 >> 24)&0xff;
                RPT(RPT_WRN,"uint32:%u",var_uint32);
                break;          
         case PARAM_COMBINE_TYPE:
			 	memcpy(msg_buf, srcBuff, FRAME_DATA_LEN);
                break;
         default:
                RPT(RPT_WRN,"cf_get_data_type_change param's type(= %u) is unknow!\n",type);
			    return -1;
     }	 
	 return 0;
}

/*****************************************************************************************
* 函数名称: udp_params_combine_set
* 函数功能: 组合参数设置
* 输入参数: combine_params: 组合参数列表；params_num:组合参数数目
           buff: 组合参数具体配置值存放空间
* 输出参数: 无
* 返回结果: 设置是否成功
* 修改记录:
******************************************************************************************/
static int udp_params_combine_set(char *buff,COMBINE_PARAM_OBJ *combine_params,int params_num)
{
	int i = 0;
	int ret = CF_SET_OK;
	
    char Databuff[MAX_PARAM_LEN] = {0};

	if(buff == NULL ||combine_params == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return CF_SET_ERROR;
	}
	
	char *pDataVal = NULL;
	pDataVal = buff;

	//组合参数中若有参数设置错误如何反馈呢?
	for(i = 0; i < params_num; i++)
	{
		ret = cf_convert_msg_to_demo(Databuff,pDataVal,combine_params[i].dataType,
			                        combine_params[i].vMax,combine_params[i].vMin);
		if(ret != CF_SET_ERROR)
		{
		   ret = udp_param_set_by_mq(combine_params[i].mapId,Databuff);
		}
		pDataVal += combine_params[i].paraLength;

	} 
	return CF_SET_OK;
}
/*****************************************************************************************
* 函数名称: udp_params_combine_get
* 函数功能: 组合参数查询
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int udp_params_combine_get(char *buff,COMBINE_PARAM_OBJ *combine_params,int params_num)
{
	int i = 0;
	int ret = 0;
	
    char Databuff[MAX_PARAM_LEN] = {0};

	if(buff == NULL ||combine_params == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}
	
	char *pDataVal = NULL;
	pDataVal = buff;
	
	for(i = 0; i < params_num; i++)
	{
		ret = udp_param_get_from_mq(combine_params[i].mapId,Databuff);

		ret = cf_convert_msg_from_demo(pDataVal,Databuff,combine_params->dataType);
		
		pDataVal += combine_params[i].paraLength;

	} 
	return 0;
}
/*****************************************************************************************
* 函数名称: udp_params_set
* 函数功能: 参数设置
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int udp_params_set(CF_PARAM_OBJ *param_obj,UDP_OBJ *UdpObj)
{
	int ret = CF_SET_OK;

	char buff[100] = {0};

	if(UdpObj == NULL ||param_obj == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return CF_SET_ERROR;
	}

	CTRL_FRAME *UdpCF = &UdpObj->UdpCF;

	if (param_obj->rd_wr_attr == CF_READ_ONLY)
	{
		RPT(RPT_ERR, "udp_params_set param READ_ONLY !\n");
		return CF_SET_ERROR;
	}
	
	ret = cf_convert_msg_to_demo(buff,UdpCF->ctrl_data,param_obj->data_type,
		                              param_obj->max_value,param_obj->min_value);
	if (ret == CF_SET_ERROR)
	{
		return ret;
	}
	//RPT(RPT_WRN, "udp param set start %s",buff);

	if (param_obj->cmd_id != CF_COMBINE_PARAM_ID)
	{
		ret = udp_param_set_by_mq(param_obj->map_id,buff);
	}
	else 
	{
		ret = udp_params_combine_set(buff,UdpObj->combine_params,UdpObj->combine_params_num);
	}
	//RPT(RPT_WRN, "udp param set end ret = %d",ret);
	return ret;
}
/*****************************************************************************************
* 函数名称: udp_params_get
* 函数功能: 参数查询
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int udp_params_get(CF_PARAM_OBJ *param_obj,UDP_OBJ *UdpObj)
{
	int ret = 0;

	char buff[100] = {0};

	if(UdpObj == NULL ||param_obj == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	CTRL_FRAME *UdpCF = &UdpObj->UdpCF;

	if (param_obj->rd_wr_attr == CF_WRITE_ONLY)
	{
		RPT(RPT_ERR, "udp_params_set param WRITE_ONLY !\n");
		return -1;
	}
	//RPT(RPT_WRN, "udp param get start ");

	if (param_obj->cmd_id != CF_COMBINE_PARAM_ID)
	{
		ret = udp_param_get_from_mq(param_obj->map_id,buff);
	}
	else 
	{
		ret = udp_params_combine_get(buff,UdpObj->combine_params,UdpObj->combine_params_num);
	}

	memset(UdpCF->ctrl_data,0,FRAME_DATA_LEN);
	//strcpy(UdpCF->ctrl_data,buff);
	ret = cf_convert_msg_from_demo(UdpCF->ctrl_data,buff,param_obj->data_type);
	//RPT(RPT_WRN, "udp param get end %s",buff);
	
	return ret;

}
/*****************************************************************************************
* 函数名称: udp_param_object_get
* 函数功能: 根据控制帧 参数ID字段，获取参数属性表
* 输入参数: id:参数ID;
* 输出参数: param_obj:指向参数属性表
* 返回结果: 是否查找到；0:表示查找成功；-1表示查找失败
* 修改记录:
******************************************************************************************/
static int udp_param_object_get(int id,UDP_OBJ *UdpObj,CF_PARAM_OBJ *param_obj )
{
	CF_PARAM_OBJ_TABLE combine_param;
	CF_PARAM_OBJ_TABLE *param_table = NULL;

	CF_PARAM_OBJ * temp_param = NULL;

	int moudle_index = 0;
	int param_id = 0;
	int module_num = 0;

	int i = 0;
	int ParamFindF = 0;

	if(UdpObj == NULL ||param_obj == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	//组合参数ID
	if (id == CF_COMBINE_PARAM_ID)
	{
		param_table = &combine_param;
		param_table->param_object_table = (CF_PARAM_OBJ *)cf_combine_param_table;
		param_table->table_len = sizeof (cf_combine_param_table)/sizeof(CF_PARAM_OBJ);
		param_id      = id;
	}
	//参数模块---获取模块参数表
	else 
	{
		moudle_index = (id&0xff00)>>8;
		module_num    = UdpObj->udp_module_num;
		if (moudle_index > module_num)
		{
			RPT(RPT_ERR,"moudle index error %d = %d(Max)",moudle_index,module_num);
			return -1;
		}
		param_table =(CF_PARAM_OBJ_TABLE *) &(UdpObj->udp_module_table[moudle_index]);
		param_id      = (id&0x00ff);
		RPT(RPT_WRN,"moudle index = %d,param id max = %d",moudle_index,UdpObj->udp_module_table[moudle_index].table_len);

		if (param_id > param_table->table_len)
		{
			RPT(RPT_ERR,"param id error %d = %d(Max)",param_id,param_table->table_len);
			return -1;
		}
	}

	RPT(RPT_WRN,"moudle index = %d,param id = %d",moudle_index,param_id);

	//根据param_id 查找参数表，得到相应参数属性表
	for (i = 0;i < param_table->table_len;i++)
	{
		temp_param = &(param_table->param_object_table[i]);
		if (param_id == temp_param->cmd_id)
		{
			*param_obj = *temp_param;
			ParamFindF = 1;
			break;
		}
	}

	if (i == param_table->table_len)
	{
		ParamFindF = -1;
	}

	RPT(RPT_WRN,"cmdid = %d,mapid = %d,datatype = %d,max = %d",param_obj->cmd_id,param_obj->map_id,param_obj->data_type,
		                                         param_obj->max_value);
	RPT(RPT_WRN,"param id max = %d",UdpObj->udp_module_table[0].table_len);
	return ParamFindF;
}
/*****************************************************************************************
* 函数名称: udp_frame_param_handle
* 函数功能: 解析参数ID字段，并进行参数设置/查询
* 输入参数: 
* 输出参数: 无
* 返回结果: -1:表示参数ID解析失败，未找到相应的参数属性表
           0:表示参数设置/查询成功
* 修改记录:
******************************************************************************************/
static int udp_frame_param_handle(UDP_OBJ *UdpObj)
{
	int ret = 0;
	int id = 0;
	
	char SetGFlag = 0;

	CF_PARAM_OBJ param_obj;

	if(UdpObj == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	CTRL_FRAME *UdpCF = &UdpObj->UdpCF;
	
	id            = UdpCF->ctrl_id;
	RPT(RPT_WRN, "udp ctrl_id = %d ",id);
	RPT(RPT_WRN,"param id max = %d",UdpObj->udp_module_table[0].table_len);
	if (udp_param_object_get(id,UdpObj,&param_obj)<0)
	{
		return -1;
	}
	//RPT(RPT_WRN, "udp param set or get start ");
	
	SetGFlag = UdpCF->ctrl_set_get;
	if (SetGFlag == FRAME_SET_VAL)
	{
		ret = udp_params_set(&param_obj,UdpObj);
		
		UdpObj->flags = ret;
	}
	else if (SetGFlag == FRAME_GET_VAL)
	{
		ret = udp_params_get(&param_obj,UdpObj);
	}

	RPT(RPT_WRN,"param id max = %d",UdpObj->udp_module_table[0].table_len);

	return 0;
	
}
/*****************************************************************************************
* 函数名称: udp_ctrl_frame_opt_get
* 函数功能: 解析接收到的数据；获取控制帧各字段
* 输入参数: buff:sock线程接收到的数据；
           DevId:本地设备ID
* 输出参数: UdpCF:指向控制帧结构
* 返回结果: 解析成功:CF_CMD_OK;解析失败:CF_CMD_ERROR
* 修改记录:
******************************************************************************************/
static int udp_ctrl_frame_opt_get(char *buff,int CmdNum,int DevId,CTRL_FRAME *UdpCF)
{
	int Anl_Len = 0;
	int i = 0;
	char TCheck = 0;
	unsigned int CheckVal = 0;
	char RecvData[100] = {0};

	if(buff == NULL ||UdpCF == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return CF_CMD_ERROR;
	}
	
	//起始字段
	UdpCF->ctrl_start = *buff;
	if (UdpCF->ctrl_start != FRAME_START_VAL)
	{
		RPT(RPT_ERR, "udp frame[%d] ctrl_start error = %d",CmdNum,UdpCF->ctrl_start);
		return CF_CMD_ERROR;
	}
	//RPT(RPT_WRN,"ctrl_start = 0x%X",UdpCF->ctrl_start);
	Anl_Len += sizeof(char);

	//设备ID,在0x1000~0xfffe之间；0x0000为广播地址；0x0001~0x0fff保留
	UdpCF->ctrl_dev_id = *((unsigned short*)(buff+Anl_Len));
	//UdpCF->ctrl_dev_id = ntohs(UdpCF->ctrl_dev_id);
	if (UdpCF->ctrl_dev_id != DevId && UdpCF->ctrl_dev_id != CF_BROADCAST_ID)
	{
		RPT(RPT_ERR, "udp frame[%d] ctrl_dev_id error = %d",CmdNum,UdpCF->ctrl_dev_id);
		return CF_CMD_ERROR;
	}
	//RPT(RPT_WRN,"ctrl_dev_id = 0x%X",UdpCF->ctrl_dev_id);
	Anl_Len += sizeof(unsigned short);

	//命令/应答
	UdpCF->ctrl_order_ack = *(buff+Anl_Len);
	if (UdpCF->ctrl_order_ack != FRAME_ORDER_VAL)
	{
		RPT(RPT_ERR, "udp frame[%d] ctrl_order_ack error = %d",CmdNum,UdpCF->ctrl_order_ack);
		return CF_CMD_ERROR;
	}
	//RPT(RPT_WRN,"ctrl_order_ack = 0x%X",UdpCF->ctrl_order_ack);
	Anl_Len += sizeof(char);

	//设置/查询
	UdpCF->ctrl_set_get = *(buff+Anl_Len);
	if (UdpCF->ctrl_set_get != FRAME_SET_VAL && UdpCF->ctrl_set_get != FRAME_GET_VAL)
	{
		RPT(RPT_ERR, "udp frame[%d] ctrl_set_get error = %d",CmdNum,UdpCF->ctrl_set_get);
		return CF_CMD_ERROR;
	}
	//RPT(RPT_WRN,"ctrl_set_get = 0x%X",UdpCF->ctrl_set_get);
	Anl_Len += sizeof(char);

	//命令id
	UdpCF->ctrl_id = *((unsigned int*)(buff+Anl_Len));
	//UdpCF->ctrl_id = ntohl(UdpCF->ctrl_id);
	//RPT(RPT_WRN,"ctrl_id = 0x%X",UdpCF->ctrl_id);
	Anl_Len += sizeof(unsigned int);

	//数据
	memcpy(UdpCF->ctrl_data,(buff+Anl_Len),FRAME_DATA_LEN);
	//数据打印
	for (i = 0;i< FRAME_DATA_LEN;i++)
	{
		sprintf(RecvData +i*2,"%02X",(unsigned char)UdpCF->ctrl_data[i]);
	}
	//RPT(RPT_WRN,"ctrl_data = 0x%s",RecvData);
	Anl_Len += FRAME_DATA_LEN;

	//计算校验值
	for (i = 0;i < Anl_Len;i++)
	{
		TCheck = *(buff+i);
		CheckVal += TCheck;
	}
	//校验
	UdpCF->ctrl_check = *(buff+Anl_Len);
	if (UdpCF->ctrl_check != (CheckVal&0xff))
	{
		return CF_CMD_ERROR;
	}
	Anl_Len += sizeof(char);

	//结束字段
	UdpCF->ctrl_end = *(buff+Anl_Len);
	if(UdpCF->ctrl_end != FRAME_END_VAL)
	{
		return CF_CMD_ERROR;
	}
	Anl_Len += sizeof(char);
	//RPT(RPT_WRN,"udp analysis success %d",Anl_Len);
	return CF_CMD_OK;
}
/*****************************************************************************************
* 函数名称: udp_msg_cmd_valid
* 函数功能: 
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int udp_msg_cmd_valid(CTRL_FRAME *CurrCF,int DevID,int CmdNum)
{
	int ret = 0;

	if(CurrCF == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}
	
	//判断设备ID
	if (CurrCF->ctrl_dev_id != DevID && CurrCF->ctrl_dev_id != CF_BROADCAST_ID)
	{
		RPT(RPT_ERR, "udp frame[%d] ctrl dev_id error = %d",CmdNum,CurrCF->ctrl_dev_id);

		ret = -1;
	}

	//判断是否是命令帧
	if (CurrCF->ctrl_order_ack != FRAME_ORDER_VAL)
	{
		RPT(RPT_ERR, "udp frame[%d] ctrl order_ack error = %d",CmdNum,CurrCF->ctrl_order_ack);
		
		ret = -1;
	}

    //判断结束码
    if (CurrCF->ctrl_end != FRAME_END_VAL)
    {
    	RPT(RPT_ERR, "udp frame[%d] ctrl end error = %d",CmdNum,CurrCF->ctrl_end);

		ret = -1;
    }
    //判断校验码
	if (CurrCF->ctrl_check != CTRL_FRAME_LEN -FRAME_END_LEN - FRAME_CHECK_LEN)
    {
    	RPT(RPT_ERR, "udp frame[%d] ctrl check error = %d",CmdNum,CurrCF->ctrl_check);

		ret = -1;
    }

	if (CurrCF->ctrl_set_get != FRAME_SET_VAL && CurrCF->ctrl_set_get != FRAME_GET_VAL) 
	{
		RPT(RPT_ERR, "udp frame[%d] ctrl set_get error = %d",CmdNum,CurrCF->ctrl_set_get);

		ret = -1;
	}

	return ret;
}
/*****************************************************************************************
* 函数名称: udp_start_sec_get
* 函数功能: 从接收到的数据中 搜寻控制帧起始字段
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int udp_start_sec_get(char *buff,int SFirst,int MaxSize)
{
	int i = 0;

	if(buff == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}
	
	//搜寻起始字段
	for (i = SFirst;i < MaxSize;i ++)
	{
		if (buff[i] == FRAME_START_VAL)
		{
			if (i + CTRL_FRAME_LEN > MaxSize)
			{
				return -1;
			}
			//判断相应结束码是否正确
			if (buff[i + CTRL_FRAME_LEN - 1] != FRAME_END_VAL)
			{
				//此起始码位置错误，丢掉
				continue;
			}
			else 
			{
				//此起始码位置ok,停止搜寻
				break;
			}
		}
	}

	if (i == MaxSize)
	{
		return -1;
	}

	return i;
}
/*****************************************************************************************
* 函数名称: udp_recv_msg_analysis
* 函数功能: 控制帧解析
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static void udp_recv_msg_analysis(UDP_OBJ *UdpObj)
{
	int RecvDSize = 0;
	int TmpDSize = 0;
	int CmdNum = 0;
	int StartPos = 0;
	int ret = 0;

	unsigned short dev_id = 0;
	
	CTRL_FRAME *UdpCF;
	SOCK_BUFF_OBJ *pSockBuff = NULL;
	char *pRecvBuff = NULL;
	char *pSndBuff = NULL;

	if(UdpObj == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return;
	}

	dev_id   = UdpObj->local_dev_id;
	UdpCF    = &(UdpObj->UdpCF);
	
	pSockBuff = UdpObj->udp_sock_buff;
	pRecvBuff = (char*)pSockBuff->RecvBuff;
	RecvDSize = pSockBuff->RecvDataLen;

	pSndBuff  = (char*)pSockBuff->SndBuff;
	memset(pSndBuff,0,pSockBuff->SndDataLen);
	pSockBuff->SndDataLen = 0;
	if (RecvDSize < CTRL_FRAME_LEN)
	{
		RPT(RPT_ERR, "udp frame len error = %d",RecvDSize);
		UdpObj->flags = CF_CMD_ERROR;
		udp_send_to_sock(UdpObj);
		return;
	}
	
	//解析命令
	while (TmpDSize < RecvDSize)
	{
		//每次某条命令之前清除发送buff
		memset(UdpCF,0,sizeof(CTRL_FRAME));
		UdpObj->flags = CF_CMD_OK;
		//查找起始字段，有个问题待商榷:丢掉起始字段或是结束字段错误的帧而不反馈是否合适?
		StartPos = udp_start_sec_get(pRecvBuff,TmpDSize,RecvDSize);
		if (StartPos < 0)
		{
			break;
		}
		//当前帧起始码位置
		TmpDSize = StartPos;
		//获取当前控制帧数据
		ret = udp_ctrl_frame_opt_get((pRecvBuff+TmpDSize),CmdNum,dev_id,UdpCF);
		if (ret == CF_CMD_ERROR)
		{
			UdpObj->flags = ret;
			udp_send_to_sock(UdpObj);
			continue;
		}

		if (udp_frame_param_handle(UdpObj) < 0)
		{
			UdpObj->flags = CF_CMD_ERROR;
		}
		
		RPT(RPT_WRN,"param id max = %d",UdpObj->udp_module_table[0].table_len);
		TmpDSize += CTRL_FRAME_LEN;
		CmdNum++;
		udp_send_to_sock(UdpObj);
	}

	RPT(RPT_WRN,"param id max = %d",UdpObj->udp_module_table[0].table_len);
	if (CmdNum == 0)
	{
		RPT(RPT_ERR, "udp recv cmd error ");
		char sndStr[10] = "you ok ?";
		pSockBuff->SndDataLen = strlen(sndStr);
		memcpy(pSndBuff,sndStr,pSockBuff->SndDataLen);
	}
}
/*****************************************************************************************
* 函数名称: udp_msg_pthread
* 函数功能: udp 控制协议线程
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static void udp_msg_pthread(udp_handle h)
{
	UDP_OBJ *handle = h;

	while (1)
	{
		if (sock_snd_flag_get(handle->SockObj) == false)
		{
		    udp_recv_msg_analysis(handle);

			sock_snd_flag_set(handle->SockObj,true);
			
			RPT(RPT_WRN,"param id max = %d",handle->udp_module_table[0].table_len);
			//等待sock线程 发送成功
			//suma_mssleep(3000);
		}
	}
}
/*****************************************************************************************
* 函数名称: udp_module_table_init
* 函数功能: 参数module注册
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static int udp_module_table_init(CF_PARAM_OBJ_TABLE *module_table)
{  
    int i = 0;

	if(module_table == NULL)
	{
		RPT(RPT_ERR,"NULL pointer!\n");
		return -1;
	}

	//以下模块注册顺序不能改变
    module_table[i/*0*/].table_len = cf_module_table_len(cf_sys_param_table);
    module_table[i++].param_object_table = (CF_PARAM_OBJ*)cf_sys_param_table;

	module_table[i/*1*/].table_len = cf_module_table_len(cf_snd_param_table);
    module_table[i++].param_object_table = (CF_PARAM_OBJ*)cf_snd_param_table;
	
	module_table[i/*2*/].table_len = cf_module_table_len(cf_videnc_param_table);
    module_table[i++].param_object_table = (CF_PARAM_OBJ*)cf_videnc_param_table;
    
	module_table[i/*3*/].table_len = cf_module_table_len(cf_audenc_param_table);
    module_table[i++].param_object_table = (CF_PARAM_OBJ*)cf_audenc_param_table;
    
	module_table[i/*4*/].table_len = cf_module_table_len(cf_osdenc_param_table);
    module_table[i++].param_object_table = (CF_PARAM_OBJ*)cf_osdenc_param_table;

	module_table[i/*5*/].table_len = cf_module_table_len(cf_recv_param_table);
    module_table[i++].param_object_table = (CF_PARAM_OBJ*)cf_recv_param_table;
    
	module_table[i/*6*/].table_len = cf_module_table_len(cf_auddec_param_table);
    module_table[i++].param_object_table = (CF_PARAM_OBJ*)cf_auddec_param_table;
    
	module_table[i/*7*/].table_len = cf_module_table_len(cf_osddec_param_table);
    module_table[i++].param_object_table = (CF_PARAM_OBJ*)cf_osddec_param_table;

    module_table[i/*8*/].table_len = cf_module_table_len(cf_status_param_table);
    module_table[i].param_object_table = (CF_PARAM_OBJ*)cf_status_param_table;

    return i;
}
/*****************************************************************************************
* 函数名称: udp_msg_pthread_create
* 函数功能: udp控制协议解析线程创建
* 输入参数: sock_h:sock线程句柄
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
static udp_handle udp_msg_pthread_create(sockets_handle sock_h)
{
	SOCK_OBJ *sock_handle = NULL;
	UDP_OBJ *handle = NULL;

	int module_num = 0;

	handle = (UDP_OBJ *)calloc(1,sizeof(UDP_OBJ));
	if (NULL == handle)
	{
		RPT(RPT_ERR,"udp handle create failed");

		return handle;
	}

	handle->SockObj = sock_h;

	sock_handle = handle->SockObj;
	handle->udp_sock_buff = &(sock_handle->sock_buff);

	//参数模块初始化
	memset(handle->udp_module_table, 0, sizeof(handle->udp_module_table));
	//RPT(RPT_WRN, "udp module size %d = %d",sizeof(handle->udp_module_table),sizeof(CF_PARAM_OBJ_TABLE));
	module_num = udp_module_table_init(handle->udp_module_table);
	if (module_num > 255 || module_num < 0)
	{
		RPT(RPT_ERR,"udp module num error= %d",module_num);
		free(handle);
		return NULL;
	}
	handle->udp_module_num = module_num;

	//组合参数表
	handle->combine_params = (COMBINE_PARAM_OBJ *)cf_combine_params;
	handle->combine_params_num = sizeof(cf_combine_params)/sizeof(COMBINE_PARAM_OBJ);

	//清除udp控制帧数据
	memset((char*)&(handle->UdpCF),0,sizeof(CTRL_FRAME));
#ifdef PARAM_MQ_CTRL
	param_mq_attrs attrs;
	//udp 消息队列参数
	memset(&(attrs), 0, sizeof(attrs));
	attrs.name_id = PARAM_MQ_ID_PROCESS;
	glb_udp_snd =  param_mq_create(&attrs);
	if(glb_udp_snd == NULL)
	{
		RPT(RPT_ERR,"glb_mqd_snd failed");
		exit(1);
	}
	
	attrs.name_id = PARAM_MQ_ID_UDP;
	glb_udp_recv = param_mq_create(&attrs);
	if(glb_udp_recv == NULL)
	{
		///perror("mq_open");
		RPT(RPT_ERR,"glb_web_recv failed");
		exit(1);
	}  
#endif
	//设备id 在0x1000~0xfffe之间；0x0000为广播地址；0x0001~0x0fff保留
	handle->local_dev_id = udp_device_id_get();
	if (!(((0x0fff< handle->local_dev_id) && (handle->local_dev_id < 0xffff))
		   ||(handle->local_dev_id == CF_BROADCAST_ID)))
	{
		RPT(RPT_ERR,"udp local device id error= %d",handle->local_dev_id);
		free(handle);
		return NULL;
	}
	RPT(RPT_WRN, "local_dev_id = %d",handle->local_dev_id);

	handle->tsk_stack_size = UDP_TSK_STACK_SIZE;

	return handle;
}
/*****************************************************************************************
* 函数名称: udp_msg_pthread_start
* 函数功能: udp控制协议解析线程启动
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
pthread_t udp_msg_pthread_start(udp_handle h,int priority)
{
	pthread_attr_t attr;
	struct sched_param param;

	int stack_size;

	UDP_OBJ *handle = h;

	pthread_attr_init(&attr);
	pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
	pthread_attr_getschedparam(&attr, &param);

	param.sched_priority = priority;
	pthread_attr_setschedparam(&attr, &param); 

	stack_size = handle->tsk_stack_size;
	pthread_attr_setstacksize(&attr, stack_size);

	pthread_create(&handle->tsk_id, &attr, (void *)udp_msg_pthread, h);
	RPT(RPT_WRN,"udp server start at %d priority",  priority);
	
	return handle->tsk_id;
}

/*****************************************************************************************
* 函数名称: udp_sock_start
* 函数功能: udp 控制协议 功能启动
* 输入参数: 
* 输出参数: 
* 返回结果: 
* 修改记录:
******************************************************************************************/
 void udp_sock_start(int priority)
{
	sockets_handle sock_h;
	udp_handle   udp_sock_h;
	
	SOCK_PARAM sock_params = 
	{
		SOCK_AF_IPv4,
		SOCK_UDP_DGRAM,
		SOCK_PROTO_UDP,
		SOCK_DEFAULT_IP,
		6180,
		0,
		0,
	};
	SOCK_INIT sock_init;

	sock_init.params = sock_params;
	sock_init.sock_recv_snd = SOCK_RECV_SEND;
	sock_init.RecvBuffLen = UDP_SOCK_BUFF_SIZE;
	sock_init.SndBuffLen = UDP_SOCK_BUFF_SIZE;
	sock_init.CurrOptNum = udp_sock_opt_list(&sock_init);

	//套接字线程，接收发送数据
	sock_h = sock_server_create(&sock_init);
	sock_server_start(sock_h,priority);

	//udp控制协议解析线程
	udp_sock_h = udp_msg_pthread_create(sock_h);
	udp_msg_pthread_start(udp_sock_h,priority+2);
}
void tcp_sock_start(int priority)
{
	sockets_handle h;
	udp_handle   udp_sock_h;
	
	SOCK_PARAM sock_params = 
	{
		SOCK_AF_IPv4,
		SOCK_TCP_STREAM,
		SOCK_PROTO_TCP,
		SOCK_DEFAULT_IP,
		4000,
		0,
		0,
	};

	SOCK_INIT sock_init;

	sock_init.params = sock_params;
	sock_init.sock_recv_snd = SOCK_RECV_SEND;
	sock_init.RecvBuffLen = UDP_SOCK_BUFF_SIZE;
	sock_init.SndBuffLen = UDP_SOCK_BUFF_SIZE;
	sock_init.CurrOptNum = udp_sock_opt_list(&sock_init);

	h = sock_server_create(&sock_init);
	sock_server_start(h,priority);

	//udp控制协议解析线程
	udp_sock_h = udp_msg_pthread_create(h);
	udp_msg_pthread_start(udp_sock_h,priority+2);
}










