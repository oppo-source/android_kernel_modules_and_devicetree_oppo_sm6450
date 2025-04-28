#include "oplus_cam_eeprom_beforeread.h"

struct eeprom_memory_map_init_write_params sm7435_hi846w_eeprom  ={
    .slave_addr = 0x40,
          .mem_settings =
          {
            {0x0A00, CAMERA_SENSOR_I2C_TYPE_WORD, 0x0000, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x2000, CAMERA_SENSOR_I2C_TYPE_WORD, 0x0000, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x2002, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00FF, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x2004, CAMERA_SENSOR_I2C_TYPE_WORD, 0x0000, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x2008, CAMERA_SENSOR_I2C_TYPE_WORD, 0x3FFF, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x23FE, CAMERA_SENSOR_I2C_TYPE_WORD, 0xC056, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x0A00, CAMERA_SENSOR_I2C_TYPE_WORD, 0x0000, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x0E04, CAMERA_SENSOR_I2C_TYPE_WORD, 0x0012, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x0F08, CAMERA_SENSOR_I2C_TYPE_WORD, 0x2F04, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x0F30, CAMERA_SENSOR_I2C_TYPE_WORD, 0x001F, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x0F36, CAMERA_SENSOR_I2C_TYPE_WORD, 0x001F, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x0F04, CAMERA_SENSOR_I2C_TYPE_WORD, 0x3A00, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x0F32, CAMERA_SENSOR_I2C_TYPE_WORD, 0x025A, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x0F38, CAMERA_SENSOR_I2C_TYPE_WORD, 0x025A, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x0F2A, CAMERA_SENSOR_I2C_TYPE_WORD, 0x4124, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x006A, CAMERA_SENSOR_I2C_TYPE_WORD, 0x0100, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},
            {0x004C, CAMERA_SENSOR_I2C_TYPE_WORD, 0x0100, CAMERA_SENSOR_I2C_TYPE_WORD, 0x00},

            {0x0a02, CAMERA_SENSOR_I2C_TYPE_WORD,0x01, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },
            {0x0a00, CAMERA_SENSOR_I2C_TYPE_WORD,0x00, CAMERA_SENSOR_I2C_TYPE_BYTE, 10},
            {0x0f02, CAMERA_SENSOR_I2C_TYPE_WORD,0x00, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },
            {0x071a, CAMERA_SENSOR_I2C_TYPE_WORD,0x01, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },
            {0x071b, CAMERA_SENSOR_I2C_TYPE_WORD,0x09, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },
            {0x0d04, CAMERA_SENSOR_I2C_TYPE_WORD,0x00, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },
            {0x0d00, CAMERA_SENSOR_I2C_TYPE_WORD,0x07, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },
            {0x003e, CAMERA_SENSOR_I2C_TYPE_WORD,0x10, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },
            {0x0a00, CAMERA_SENSOR_I2C_TYPE_WORD,0x01, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },

            {0x070a, CAMERA_SENSOR_I2C_TYPE_WORD,0x02, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },
            {0x070b, CAMERA_SENSOR_I2C_TYPE_WORD,0x01, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },
            {0x0702, CAMERA_SENSOR_I2C_TYPE_WORD,0x01, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },


          },
          .memory_map_size = 29,
};


struct eeprom_memory_map_init_write_params sm7435_hi846w_eeprom_after_read  ={
    .slave_addr = 0x40,
          .mem_settings =
          {
            {0x0a00, CAMERA_SENSOR_I2C_TYPE_WORD,0x00, CAMERA_SENSOR_I2C_TYPE_BYTE, 10},
            {0x003e, CAMERA_SENSOR_I2C_TYPE_WORD,0x00, CAMERA_SENSOR_I2C_TYPE_BYTE, 0 },
            {0x0a00, CAMERA_SENSOR_I2C_TYPE_WORD,0x01, CAMERA_SENSOR_I2C_TYPE_BYTE, 1 },
          },
          .memory_map_size = 3,
};

struct  OplusOtpCheckInfo sm7435_hi846w_otp_checkinfo ={
    .groupInfo =
    {
        .IsAvailable = TRUE,
        .GroupFlag   = 0x01, //group flag valid value
        .CheckItemOffset = {0x000F, 0x075A, 0x0EA5}, //Module info group flag

    },

    .ItemInfo =
    {
        { { TRUE, 0x0000, 0x0011 }, { TRUE, 0x074B, 0x0011 }, { TRUE, 0x0E96, 0x0011 }, }, //module info
        { { TRUE, 0x0011, 0x0012 }, { TRUE, 0x075C, 0x0012 }, { TRUE, 0x0EA7, 0x0012 }, }, //5000awb info
        { { TRUE, 0x0023, 0x0012 }, { TRUE, 0x076E, 0x0012 }, { TRUE, 0x0EB9, 0x0012 }, }, //3000awb info
        { { TRUE, 0x0035, 0x0006 }, { TRUE, 0x0780, 0x0006 }, { TRUE, 0x0ECB, 0x0006 }, }, //5000awbOVER info
        { { TRUE, 0x003B, 0x0006 }, { TRUE, 0x0786, 0x0006 }, { TRUE, 0x0ED1, 0x0006 }, }, //3000awbOVER info
        { { TRUE, 0x0041, 0x001A }, { TRUE, 0x078C, 0x001A }, { TRUE, 0x0ED7, 0x001A }, }, //SN info
        { { TRUE, 0x005B, 0x06EA }, { TRUE, 0x07A6, 0x06EA }, { TRUE, 0x0EF1, 0x06EA }, }, //lsc info
    },
};
