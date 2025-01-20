#include "oplus_cam_insensor_eeprom_dev.h"
#define SC820CS_MAP_SIZE 1950
struct  OtpCheckInfo sc820cs_checksum_info ={
	.groupInfo =
	{
		.IsAvailable = TRUE,
		.ItemNum = 7,
		.GroupFlag   = 0x01, //group flag valid value
		// Module info, AWB 5000K , AWB 2850K , Light 5000K , Light 2850K , SN , LSC
		.CheckItemOffset = {0x000F, 0x0021, 0x0033, 0x0039, 0x003F, 0x0059, 0x0743},
	},
	.ItemInfo =
	{//   avaible, start, end, checksum
		{ TRUE, 0x0000, 0x000E, 0x0010}, //module info
		{ TRUE, 0x0011, 0x0020, 0x0022}, //AWB 5000K
		{ TRUE, 0x0023, 0x0032, 0x0034}, //AWB 2850K
		{ TRUE, 0x0035, 0x0038, 0x003A}, //Light 5000K
		{ TRUE, 0x003B, 0x003E, 0x0040}, //Light 2850K
		{ TRUE, 0x0041, 0x0058, 0x005A}, //SN
		{ TRUE, 0x005B, 0x0742, 0x0744}, //LSC
	},
};
struct camera_eeprom_map_info sc820cs_map_info = {
	.page_num = 10,
	.group_num = 2,
	.page_num_pergroup = 5,
	.max_retry_num = 3,
	.valid_data_size = 0x79E, // group 1 /2
	.eeprom_page_map =
	{//valid_size   addr   addr_type   data_type
		{390, 0x827A, CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_BYTE}, // page2
		{390, 0x847A, CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_BYTE}, // page3
		{390, 0x867A, CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_BYTE}, // page4
		{390, 0x887A, CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_BYTE}, // page5
		{390, 0x8A7A, CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_BYTE}, // page6
		{390, 0x8C7A, CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_BYTE}, // page7
		{390, 0x8E7A, CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_BYTE}, // page8
		{390, 0x907A, CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_BYTE}, // page9
		{390, 0x927A, CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_BYTE}, // page10
		{390, 0x947A, CAMERA_SENSOR_I2C_TYPE_WORD, CAMERA_SENSOR_I2C_TYPE_BYTE}, // page11
	},
};
struct camera_eeprom_reg_info sc820cs_regs_info = {
	.slave_addr = 0x6c,
	.init_regs_num = 3,
	.load_regs_num = 8,
	.init_regs =
	{     // reg_addr, reg_data, delay, data_mask
		{// R0
			{0x36b0,   0x48,   0x00,   0x00},
			{0x36b1,   0x38,   0x00,   0x00},
			{0x36b2,   0x41,   0x00,   0x00},
		},
		{// Rn2
			{0x36b0,   0x48,   0x00,   0x00},
			{0x36b1,   0x18,   0x00,   0x00},
			{0x36b2,   0x41,   0x00,   0x00},
		},
		{// R1nf
			{0x36b0,   0x48,   0x00,   0x00},
			{0x36b1,   0x58,   0x00,   0x00},
			{0x36b2,   0x41,   0x00,   0x00},
		},
	},
	.load_regs =
	{     // reg_addr, reg_data, delay, data_mask
		{// page2
			{0x4408,   0x82,   0x00, 0x00},
			{0x4409,   0x00,   0x00, 0x00},
			{0x440a,   0x83,   0x00, 0x00},
			{0x440b,   0xFF,   0x00, 0x00},
			{0x4401,   0x13,   0x00, 0x00},
			{0x4412,   0x03,   0x00, 0x00},
			{0x4407,   0x00,   0x00, 0x00},
			{0x4400,   0x11,   0x00, 0x00},
		},
		{// page3
			{0x4408,   0x84,   0x00, 0x00},
			{0x4409,   0x00,   0x00, 0x00},
			{0x440a,   0x85,   0x00, 0x00},
			{0x440b,   0xFF,   0x00, 0x00},
			{0x4401,   0x13,   0x00, 0x00},
			{0x4412,   0x05,   0x00, 0x00},
			{0x4407,   0x00,   0x00, 0x00},
			{0x4400,   0x11,   0x00, 0x00},
		},
		{// page4
			{0x4408,   0x86,   0x00, 0x00},
			{0x4409,   0x00,   0x00, 0x00},
			{0x440a,   0x87,   0x00, 0x00},
			{0x440b,   0xFF,   0x00, 0x00},
			{0x4401,   0x13,   0x00, 0x00},
			{0x4412,   0x07,   0x00, 0x00},
			{0x4407,   0x00,   0x00, 0x00},
			{0x4400,   0x11,   0x00, 0x00},
		},
		{// page5
			{0x4408,   0x88,   0x00, 0x00},
			{0x4409,   0x00,   0x00, 0x00},
			{0x440a,   0x89,   0x00, 0x00},
			{0x440b,   0xFF,   0x00, 0x00},
			{0x4401,   0x13,   0x00, 0x00},
			{0x4412,   0x09,   0x00, 0x00},
			{0x4407,   0x00,   0x00, 0x00},
			{0x4400,   0x11,   0x00, 0x00},
		},
		{// page6
			{0x4408,   0x8A,   0x00, 0x00},
			{0x4409,   0x00,   0x00, 0x00},
			{0x440a,   0x8B,   0x00, 0x00},
			{0x440b,   0xFF,   0x00, 0x00},
			{0x4401,   0x13,   0x00, 0x00},
			{0x4412,   0x0B,   0x00, 0x00},
			{0x4407,   0x00,   0x00, 0x00},
			{0x4400,   0x11,   0x00, 0x00},
		},
		{// page7
			{0x4408,   0x8C,   0x00, 0x00},
			{0x4409,   0x00,   0x00, 0x00},
			{0x440a,   0x8D,   0x00, 0x00},
			{0x440b,   0xFF,   0x00, 0x00},
			{0x4401,   0x13,   0x00, 0x00},
			{0x4412,   0x0D,   0x00, 0x00},
			{0x4407,   0x00,   0x00, 0x00},
			{0x4400,   0x11,   0x00, 0x00},
		},
		{// page8
			{0x4408,   0x8E,   0x00, 0x00},
			{0x4409,   0x00,   0x00, 0x00},
			{0x440a,   0x8F,   0x00, 0x00},
			{0x440b,   0xFF,   0x00, 0x00},
			{0x4401,   0x13,   0x00, 0x00},
			{0x4412,   0x0F,   0x00, 0x00},
			{0x4407,   0x00,   0x00, 0x00},
			{0x4400,   0x11,   0x00, 0x00},
		},
		{// page9
			{0x4408,   0x90,   0x00, 0x00},
			{0x4409,   0x00,   0x00, 0x00},
			{0x440a,   0x91,   0x00, 0x00},
			{0x440b,   0xFF,   0x00, 0x00},
			{0x4401,   0x13,   0x00, 0x00},
			{0x4412,   0x11,   0x00, 0x00},
			{0x4407,   0x00,   0x00, 0x00},
			{0x4400,   0x11,   0x00, 0x00},
		},
		{// page10
			{0x4408,   0x92,   0x00, 0x00},
			{0x4409,   0x00,   0x00, 0x00},
			{0x440a,   0x93,   0x00, 0x00},
			{0x440b,   0xFF,   0x00, 0x00},
			{0x4401,   0x13,   0x00, 0x00},
			{0x4412,   0x13,   0x00, 0x00},
			{0x4407,   0x00,   0x00, 0x00},
			{0x4400,   0x11,   0x00, 0x00},
		},
		{// page11
			{0x4408,   0x94,   0x00, 0x00},
			{0x4409,   0x00,   0x00, 0x00},
			{0x440a,   0x95,   0x00, 0x00},
			{0x440b,   0xFF,   0x00, 0x00},
			{0x4401,   0x13,   0x00, 0x00},
			{0x4412,   0x15,   0x00, 0x00},
			{0x4407,   0x00,   0x00, 0x00},
			{0x4400,   0x11,   0x00, 0x00},
		},
	},
};


int sc820cs_write_reg_settings(struct cam_eeprom_ctrl_t *e_ctrl, struct cam_sensor_i2c_reg_array *i2c_sesting, uint32_t regs_size){
	int rc = 0;
	struct cam_sensor_i2c_reg_setting  i2c_reg_settings = {0};
	struct cam_sensor_i2c_reg_array    *reg_sestings     = i2c_sesting;

	i2c_reg_settings.addr_type = 2;
	i2c_reg_settings.data_type = 1;
	i2c_reg_settings.size = regs_size;
	i2c_reg_settings.reg_setting = reg_sestings;
	rc = camera_io_dev_write(&e_ctrl->io_master_info,&i2c_reg_settings);
	if (rc) {
		CAM_ERR(CAM_EEPROM, "page init failed rc %d", rc);
	}

	return rc;
}

int sc820cs_page_init(struct cam_eeprom_ctrl_t *e_ctrl, int count){
	int rc = 0;
	rc = sc820cs_write_reg_settings(e_ctrl, &sc820cs_regs_info.init_regs[count][0],\
							sc820cs_regs_info.init_regs_num);
	return rc;
}

int sc820cs_page_load(struct cam_eeprom_ctrl_t *e_ctrl, int count){
	int rc = 0;
	rc = sc820cs_write_reg_settings(e_ctrl, &sc820cs_regs_info.load_regs[count][0],\
							sc820cs_regs_info.load_regs_num);
	return rc;
}

int sc820cs_page_read(struct cam_eeprom_ctrl_t *e_ctrl, uint8_t *memptr, int page_num, int offset) {
	int rc = 0;
	struct cam_eeprom_map_t *emap = &sc820cs_map_info.eeprom_page_map[page_num];

	rc = camera_io_dev_read_seq(&e_ctrl->io_master_info,
		emap->addr, &memptr[offset],
		emap->addr_type,
		emap->data_type,
		emap->valid_size);

	if (rc < 0) {
		CAM_ERR(CAM_EEPROM, "page[%d] read failed rc %d", page_num, rc);
	}

	return rc;
}

int sc820cs_otp_check(uint8_t *data) {
	int rc = 0;
	int sum = 0;
	int i,j;
	int item_num = sc820cs_checksum_info.groupInfo.ItemNum;
	struct OplusOtpGroupInfo *groupinfo = &sc820cs_checksum_info.groupInfo;
	struct OtpItemInfo *iteminfo = &sc820cs_checksum_info.ItemInfo[0];

	for (i = 0; i < item_num; i++) {
		sum = 0;
		if (data[groupinfo->CheckItemOffset[i]] != groupinfo->GroupFlag){
			CAM_ERR(CAM_EEPROM, "data[%d] flag : addr[0x%x]:0x%x  invalid  ", i, groupinfo->CheckItemOffset[i], data[groupinfo->CheckItemOffset[i]]);
			return -1;
		}

		for (j=iteminfo[i].start_addr; j <= iteminfo[i].end_addr; j++){
			sum += data[j];
		}

		if((sum%255) != data[iteminfo[i].checksum_addr]){
			CAM_ERR(CAM_EEPROM, "data[%d] checksum failed 0x%x : 0x%x", i, (sum%255), data[iteminfo[i].checksum_addr]);
			return -1;
		} else {
			CAM_INFO(CAM_EEPROM, "data[%d] checksum success 0x%x : 0x%x", i, (sum%255), data[iteminfo[i].checksum_addr]);
		}
	}

	return rc;
}


int oplus_cam_eeprom_sc820cs(struct cam_eeprom_ctrl_t *e_ctrl, uint8_t *data)
{
	int          rc = 0;
	int          try_num, read_data_num,idx;
	int          select_group = -1;

   	int          retry_count = sc820cs_map_info.max_retry_num;
   	int          page_count = sc820cs_map_info.page_num;
   	int          page_num_pergroup = sc820cs_map_info.page_num_pergroup;
	int          mem_size = sc820cs_map_info.valid_data_size;//1950
	uint8_t      sc820cs_otpdata[SC820CS_MAP_SIZE] = {0};

	CAM_INFO(CAM_EEPROM, "start oplus_cam_eeprom_sc820cs, i2c:0x%x", e_ctrl->io_master_info.cci_client->sid);
	memset(&sc820cs_otpdata, 0, sizeof(sc820cs_otpdata));
	for (try_num=0; try_num < retry_count; try_num++){
		rc = sc820cs_page_init(e_ctrl, try_num);
		if (rc) {
			CAM_ERR(CAM_EEPROM, "page init failed rc %d ,try times: %d", rc, try_num);
			return rc;
		}

		read_data_num = 0;
		for (idx = 0; idx < page_count; idx++) {
			rc = sc820cs_page_load(e_ctrl, idx);
			if (rc) {
				CAM_ERR(CAM_EEPROM, "page[%d] load failed rc %d", try_num, idx, rc);
				return rc;
			}

			msleep(10);
			rc = sc820cs_page_read(e_ctrl, &sc820cs_otpdata[0], idx, read_data_num);
			if (rc < 0) {
				CAM_ERR(CAM_EEPROM, "page[%d] read failed rc %d", idx, rc);
				return rc;
			}

			read_data_num += sc820cs_map_info.eeprom_page_map[idx].valid_size;

			if((idx+1)%page_num_pergroup == 0){
				select_group = (idx+1)/page_num_pergroup -1;
				rc = sc820cs_otp_check(&sc820cs_otpdata[0]);
				if (rc != 0) {
					read_data_num = 0;
					CAM_ERR(CAM_EEPROM, "group[%d] checksum fail, read next group", select_group);
					memset(sc820cs_otpdata, 0, sizeof(sc820cs_otpdata));
				} else {
					CAM_INFO(CAM_EEPROM, "group[%d] read and checksum success", select_group);
					break ;
				}
			}
		}

		if (!rc) {
			memcpy((void *)data, &sc820cs_otpdata[0], mem_size);
			break;
		}
	}

	if (try_num >= retry_count && rc) {
		CAM_ERR(CAM_EEPROM, "read otp fail, bad otp !");
		return -1;
	}

	return rc;
}


