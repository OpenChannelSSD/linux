#ifndef __LINUX_BQ27X00_BATTERY_H__
#define __LINUX_BQ27X00_BATTERY_H__

enum bq27xxx_chip {
	BQ27000 = 1, /* bq27000, bq27200 */
	BQ27010, /* bq27010, bq27210 */
	BQ2750X, /* bq27500 deprecated alias */
	BQ2751X, /* bq27510, bq27520 deprecated alias */
	BQ27500, /* bq27500/1 */
	BQ27510G1, /* bq27510G1 */
	BQ27510G2, /* bq27510G2 */
	BQ27510G3, /* bq27510G3 */
	BQ27520G1, /* bq27520G1 */
	BQ27520G2, /* bq27520G2 */
	BQ27520G3, /* bq27520G3 */
	BQ27520G4, /* bq27520G4 */
	BQ27530, /* bq27530, bq27531 */
	BQ27541, /* bq27541, bq27542, bq27546, bq27742 */
	BQ27545, /* bq27545 */
	BQ27421, /* bq27421, bq27425, bq27441, bq27621 */
};

/**
 * struct bq27xxx_plaform_data - Platform data for bq27xxx devices
 * @name: Name of the battery.
 * @chip: Chip class number of this device.
 * @read: HDQ read callback.
 *	This function should provide access to the HDQ bus the battery is
 *	connected to.
 *	The first parameter is a pointer to the battery device, the second the
 *	register to be read. The return value should either be the content of
 *	the passed register or an error value.
 */
struct bq27xxx_platform_data {
	const char *name;
	enum bq27xxx_chip chip;
	int (*read)(struct device *dev, unsigned int);
};

struct bq27xxx_device_info;
struct bq27xxx_access_methods {
	int (*read)(struct bq27xxx_device_info *di, u8 reg, bool single);
};

struct bq27xxx_reg_cache {
	int temperature;
	int time_to_empty;
	int time_to_empty_avg;
	int time_to_full;
	int charge_full;
	int cycle_count;
	int capacity;
	int energy;
	int flags;
	int power_avg;
	int health;
};

struct bq27xxx_device_info {
	struct device *dev;
	int id;
	enum bq27xxx_chip chip;
	const char *name;
	struct bq27xxx_access_methods bus;
	struct bq27xxx_reg_cache cache;
	int charge_design_full;
	unsigned long last_update;
	struct delayed_work work;
	struct power_supply *bat;
	struct list_head list;
	struct mutex lock;
	u8 *regs;
};

void bq27xxx_battery_update(struct bq27xxx_device_info *di);
int bq27xxx_battery_setup(struct bq27xxx_device_info *di);
void bq27xxx_battery_teardown(struct bq27xxx_device_info *di);

#endif
