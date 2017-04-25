/*
 * STMicroelectronics st_lsm6dsx sensor driver
 *
 * Copyright 2016 STMicroelectronics Inc.
 *
 * Lorenzo Bianconi <lorenzo.bianconi@st.com>
 * Denis Ciocca <denis.ciocca@st.com>
 *
 * Licensed under the GPL-2.
 */

#ifndef ST_LSM6DSX_H
#define ST_LSM6DSX_H

#include <linux/device.h>

#define ST_LSM6DS3_DEV_NAME	"lsm6ds3"
#define ST_LSM6DSM_DEV_NAME	"lsm6dsm"

enum st_lsm6dsx_hw_id {
	ST_LSM6DS3_ID,
	ST_LSM6DSM_ID,
};

#define ST_LSM6DSX_CHAN_SIZE		2
#define ST_LSM6DSX_SAMPLE_SIZE		6
#define ST_LSM6DSX_SAMPLE_DEPTH		(ST_LSM6DSX_SAMPLE_SIZE / \
					 ST_LSM6DSX_CHAN_SIZE)

#if defined(CONFIG_SPI_MASTER)
#define ST_LSM6DSX_RX_MAX_LENGTH	256
#define ST_LSM6DSX_TX_MAX_LENGTH	8

struct st_lsm6dsx_transfer_buffer {
	u8 rx_buf[ST_LSM6DSX_RX_MAX_LENGTH];
	u8 tx_buf[ST_LSM6DSX_TX_MAX_LENGTH] ____cacheline_aligned;
};
#endif /* CONFIG_SPI_MASTER */

struct st_lsm6dsx_transfer_function {
	int (*read)(struct device *dev, u8 addr, int len, u8 *data);
	int (*write)(struct device *dev, u8 addr, int len, u8 *data);
};

struct st_lsm6dsx_reg {
	u8 addr;
	u8 mask;
};

struct st_lsm6dsx_settings {
	u8 wai;
	u16 max_fifo_size;
	enum st_lsm6dsx_hw_id id;
};

enum st_lsm6dsx_sensor_id {
	ST_LSM6DSX_ID_ACC,
	ST_LSM6DSX_ID_GYRO,
	ST_LSM6DSX_ID_MAX,
};

enum st_lsm6dsx_fifo_mode {
	ST_LSM6DSX_FIFO_BYPASS = 0x0,
	ST_LSM6DSX_FIFO_CONT = 0x6,
};

/**
 * struct st_lsm6dsx_sensor - ST IMU sensor instance
 * @id: Sensor identifier.
 * @hw: Pointer to instance of struct st_lsm6dsx_hw.
 * @gain: Configured sensor sensitivity.
 * @odr: Output data rate of the sensor [Hz].
 * @watermark: Sensor watermark level.
 * @sip: Number of samples in a given pattern.
 * @decimator: FIFO decimation factor.
 * @decimator_mask: Sensor mask for decimation register.
 * @delta_ts: Delta time between two consecutive interrupts.
 * @ts: Latest timestamp from the interrupt handler.
 */
struct st_lsm6dsx_sensor {
	enum st_lsm6dsx_sensor_id id;
	struct st_lsm6dsx_hw *hw;

	u32 gain;
	u16 odr;

	u16 watermark;
	u8 sip;
	u8 decimator;
	u8 decimator_mask;

	s64 delta_ts;
	s64 ts;
};

/**
 * struct st_lsm6dsx_hw - ST IMU MEMS hw instance
 * @dev: Pointer to instance of struct device (I2C or SPI).
 * @irq: Device interrupt line (I2C or SPI).
 * @lock: Mutex to protect read and write operations.
 * @fifo_lock: Mutex to prevent concurrent access to the hw FIFO.
 * @fifo_mode: FIFO operating mode supported by the device.
 * @enable_mask: Enabled sensor bitmask.
 * @sip: Total number of samples (acc/gyro) in a given pattern.
 * @iio_devs: Pointers to acc/gyro iio_dev instances.
 * @settings: Pointer to the specific sensor settings in use.
 * @tf: Transfer function structure used by I/O operations.
 * @tb: Transfer buffers used by SPI I/O operations.
 */
struct st_lsm6dsx_hw {
	struct device *dev;
	int irq;

	struct mutex lock;
	struct mutex fifo_lock;

	enum st_lsm6dsx_fifo_mode fifo_mode;
	u8 enable_mask;
	u8 sip;

	struct iio_dev *iio_devs[ST_LSM6DSX_ID_MAX];

	const struct st_lsm6dsx_settings *settings;

	const struct st_lsm6dsx_transfer_function *tf;
#if defined(CONFIG_SPI_MASTER)
	struct st_lsm6dsx_transfer_buffer tb;
#endif /* CONFIG_SPI_MASTER */
};

int st_lsm6dsx_probe(struct device *dev, int irq, int hw_id,
		     const struct st_lsm6dsx_transfer_function *tf_ops);
int st_lsm6dsx_sensor_enable(struct st_lsm6dsx_sensor *sensor);
int st_lsm6dsx_sensor_disable(struct st_lsm6dsx_sensor *sensor);
int st_lsm6dsx_fifo_setup(struct st_lsm6dsx_hw *hw);
int st_lsm6dsx_write_with_mask(struct st_lsm6dsx_hw *hw, u8 addr, u8 mask,
			       u8 val);
int st_lsm6dsx_update_watermark(struct st_lsm6dsx_sensor *sensor,
				u16 watermark);

#endif /* ST_LSM6DSX_H */
