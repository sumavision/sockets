#ifndef _PTHREAD_UDP_APP_H_
#define _PTHREAD_UDP_APP_H_

#if defined (__cplusplus)
    extern "C" {
#endif
#include <stdint.h>
#include "net_sockets.h"
/**************************************** contral protocol section ****************************************/
//#define  PARAM_MQ_CTRL



//控制帧各字段长度/BYLES
#define FRAME_START_LEN             1
#define FRAME_DEV_LEN               2
#define FRAME_OACK_LEN              1
#define FRAME_SGET_LEN              1
#define FRAME_ID_LEN                4
#define FRAME_DATA_LEN              37
#define FRAME_CHECK_LEN             1
#define FRAME_END_LEN               1

#define CTRL_FRAME_LEN              48

//控制帧各字段固定值
#define FRAME_START_VAL             0x5a

#define FRAME_ORDER_VAL             0x6a
#define FRAME_ACK_VAL               0x56
#define FRAME_ERROR_VAL             0x77

#define FRAME_SET_VAL               0x01
#define FRAME_GET_VAL               0x02

#define FRAME_END_VAL               0x54

//控制帧设备ID 广播地址
#define CF_BROADCAST_ID             0x0000


//组合参数查询/设置 参数ID
#define CF_COMBINE_PARAM_ID         0xF001

#ifndef MAX_PARAM_LEN
#define MAX_PARAM_LEN               64
#endif

//参数ID
//系统参数列表
typedef enum 
{
    CF_SYS_REBOOT = 1,   
    CF_NET_IPADDR_DATA, /*2*/
    CF_NET_MASK_DATA, /*3*/
    CF_NET_GATE_DATA, /*4*/
    CF_SYS_SNMP_IP, /*5*/
    CF_DEFAULT_PARAM, /*6*/
    CF_SYS_UART_RATE, /*7*/
    CF_SYS_SERIAL_ADDR, /*8*/
    CF_SYS_SOFT_VER, /*9*/
	CF_SYS_HARD_VER, /*10*/
    CF_SYS_PARAM_SN /*11*/
}sys_param_table_id;
//视频编码参数列表
typedef enum 
{
    CF_VIDENC_INPUT = 1,
    CF_VIDENC_SYSRATE, /*2*/
    CF_VIDENC_ENC_STD, /*3*/
    CF_VIDENC_SND_MEDIA_MODE, /*4*/
    CF_VIDENC_BITRATE, /*5*/
    CF_VIDENC_WIDTH, /*6*/
    CF_VIDENC_HEIGHT, /*7*/
    CF_VIDENC_ENC_FPS1, /*8*/
    CF_VIDENC_STATUS_STD, /*9*/
    CF_VIDENC_FORMATE, /*10*/
    CF_VIDENC_RESO, /*11*/
}videnc_param_table_id;
//音频编码参数列表
typedef enum 
{
    CF_AUDENC_CTL = 1, /*1*/
    CF_AUDENC_FORMAT, /*2*/
    CF_AUDENC_G711LAW, /*3*/
    CF_AUDENC_VOLUME /*4*/
}audenc_param_table_id;
//音频解码参数列表
typedef enum 
{
    CF_AUDDEC_CTL = 1,  
    CF_AUDDEC_CODEC, /*2*/
    CF_AUDDEC_G711LAW, /*3*/
    CF_AUDDEC_GAIN /*4*/
}auddec_param_table_id;
//发送设置参数列表
typedef enum 
{
    CF_SND_CTL = 1,  /*1*/
    CF_SND_ADDR, /*2*/
    CF_SND_PORT, /*3*/
    CF_SND_TOS, /*4*/
    CF_SND_VBV, /*5*/
    CF_SND_NO_DECODE_NOSND, /*6*/
}snd_param_table_id;
//接收设置参数列表
typedef enum 
{
    CF_RECV_CTL = 1,
    CF_RECV_MULTIMODE, /*2*/
    CF_RECV_MULTIADDR, /*3*/
    CF_RECV_PORT, /*4*/
    CF_RECV_SYNCMODE /*5*/
}recv_param_table_id;
//osd解码参数列表
typedef enum
{
    CF_OSDDEC_CTL = 1,
    CF_OSDDEC_X, /*2*/
    CF_OSDDEC_Y, /*3*/
    CF_OSDDEC_COLOR, /*4*/
    CF_OSDDEC_COLOR_EDGE, /*5*/
}osddec_params_table_id;
//osd编码参数列表
typedef enum
{
    CF_OSDENC_CTL = 1,
    CF_OSDENC_X, /*2*/
    CF_OSDENC_Y, /*3*/
    CF_OSDENC_COLOR, /*4*/
    CF_OSDENC_COLOR_EDGE, /*5*/
    CF_OSDENC_SIZE, /*6*/
    CF_OSDENC_STR /*7*/
}osdenc_params_table_id;
//状态参数查询列表
typedef enum 
{
    CF_STATUS_VIDENC_RATE = 1,
    CF_STATUS_AUDENC_RATE, /*2*/
    CF_STATUS_VIDDEC_LOST, /*3*/
    CF_STATUS_VIDDEC_RATE, /*4*/
    CF_STATUS_AUDDEC_LOST, /*5*/
    CF_STATUS_AUDDEC_RATE, /*6*/
}status_param_table_id;


//参数module 列表
typedef enum
{
	CF_SYS_PARAM = 0,
	CF_SND_PARAM,
	CF_VENC_PARAM,
	CF_AENC_PARAM,
	CF_OENC_PARAM,
	CF_RECV_PARAM,
	CF_ADEC_PARAM,
	CF_ODEC_PARAM,
	CF_STATUS_PARAM,
}CF_PARAM_MODULE;

//控制帧解析结果,查询/设置结果
typedef enum
{
	CF_CMD_OK = 0,
	CF_CMD_ERROR,

	CF_SET_OK,
	CF_SET_ERROR,
}CF_RESULT;

//参数读写表
typedef enum
{
	CF_READ_ONLY = 0,
	CF_WRITE_ONLY,
	CF_READ_WRITE,
}CF_RW_LIST;

//参数值类型
typedef enum 
{
    PARAM_STRING_TYPE = 0,
    PARAM_IP_TYPE,
    PARAM_INT8_TYPE,
    PARAM_UINT8_TYPE,
    PARAM_INT32_TYPE,
    PARAM_UINT32_TYPE,
    PARAM_XHEX_TYPE,    //添加的类型，在该类型中将数据转换为加"0X"的16进制数，并将该16进制数转换为字符串；PCR、视频、音频PID使用
    PARAM_HEX_TYPE,     //添加的类型，在该类型中将数据转换为不加"0X"的16进制数，并将该16进制数转换为字符串；串口地址使用
    PARAM_INT16_TYPE,   //for two bytes, int data
    PARAM_UINT16_TYPE,  //for two bytes, unsigned int data
    PARAM_COMBINE_TYPE
}PARAM_VAL_TYPE;

typedef struct _CF_PARAM_OBJECT_
{
    unsigned int cmd_id;   /*command ID define in ucmp protocol*/
    unsigned int map_id;    /* ID from global paramter table*/
    unsigned int data_type;
    int min_value;
    int max_value;
	int rd_wr_attr;
}CF_PARAM_OBJ;

typedef struct _CF_PARAM_OBJECT_TABLE_
{
    unsigned int table_len;
    CF_PARAM_OBJ *param_object_table;
}CF_PARAM_OBJ_TABLE;

typedef enum 
{
    CF_COMBINE_PARAM = 1,
}COMBINE_ID_TABLE;
typedef struct _COMBINE_PARAM_OBJ_
{
	uint32_t mapId;
    int paraLength;
    uint32_t dataType;
    int32_t vMin;
    int32_t vMax;    
}COMBINE_PARAM_OBJ;

//控制帧定义
typedef struct _CTRL_FRAME_
{
	char ctrl_start;
	unsigned short ctrl_dev_id;
	char ctrl_order_ack;
	
	unsigned int ctrl_id;

	char ctrl_set_get;
	char ctrl_check;
	char ctrl_end;
	char ctrl_data[FRAME_DATA_LEN];
	
}CTRL_FRAME;

#define cf_module_table_len(table) (sizeof(table) / sizeof(CF_PARAM_OBJ))
/**************************************** UDP contral protocol ****************************************/
#define UDP_SOCK_BUFF_SIZE       1024

typedef void* udp_handle;

//udp sock
typedef struct _UDP_OBJECT_
{
	/*解析结果*/
	char flags;

	/*线程stack size*/
	int tsk_stack_size;
	/*线程ID*/
	pthread_t tsk_id;

	unsigned short local_dev_id;
	
	COMBINE_PARAM_OBJ *combine_params;
	int combine_params_num;

	SOCK_OBJ * SockObj;
	SOCK_BUFF_OBJ *udp_sock_buff;
	
	CTRL_FRAME UdpCF;

	CF_PARAM_OBJ_TABLE udp_module_table[256];
	int udp_module_num;
}UDP_OBJ;





void udp_sock_start(int priority);

#if defined (__cplusplus)
}
#endif

#endif
