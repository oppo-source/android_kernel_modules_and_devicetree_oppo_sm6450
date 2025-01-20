#ifndef EEPROM_WRITE_INIT_PARAMS_BEFORE_READ_CAL_DATA_H_
#define EEPROM_WRITE_INIT_PARAMS_BEFORE_READ_CAL_DATA_H_

#define EEPROM_MEMORY_MAP_MAX_SIZE  300
#define sm7435_hi846w_i2c_slave_addr 0x40
#define WT_OTP_DATA_LEN          0x2000
#define SM7435_HI846W_OTP_DATA_LEN   0x15a3

enum checkItem {
    CHECKMODULEINFO,
    CHECKAWBD50,
    CHECKAWBA,
    CHECKAWBOVERD50,
    CHECKAWBOVERA,
    CHECKSN,
    CHECKLSC,
    CHECKNUMMAX,
};

enum groupNum {
    GROUPNUM0,
    GROUPNUM1,
    GROUPNUM2,
    GROUPNUMMAX,
};

struct OtpGroupInfo
{
    uint32_t    IsAvailable;
    uint32_t  CheckItemOffset[GROUPNUMMAX];
    uint32_t  GroupFlag;
    uint32_t  SelectGroupNum;
};

struct OtpCheckPartInfo
{
    uint32_t  IsAvailable;
    uint32_t  Offset;
    uint32_t  Length;
};

struct OplusOtpCheckInfo
{
    struct OtpGroupInfo groupInfo;
    struct OtpCheckPartInfo ItemInfo[CHECKNUMMAX][GROUPNUMMAX];
};

struct camera_reg_settings_t{
    uint32_t reg_addr;
    enum camera_sensor_i2c_type addr_type;
    uint32_t reg_data;
    enum camera_sensor_i2c_type data_type;
    uint32_t delay;
};

struct eeprom_memory_map_init_write_params{
    uint32_t slave_addr;
    struct camera_reg_settings_t mem_settings[EEPROM_MEMORY_MAP_MAX_SIZE];
    uint32_t memory_map_size;
};


int eeprom_memory_map_read_data(uint32_t slave_addr,struct cam_eeprom_memory_map_t emap,
                                struct cam_eeprom_ctrl_t *e_ctrl,uint8_t *memptr);

int eeprom_memory_map_unint_para(uint32_t slave_addr,struct cam_eeprom_ctrl_t *e_ctrl);
#endif
