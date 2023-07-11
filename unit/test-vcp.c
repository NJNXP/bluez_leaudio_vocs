// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2023 NXP
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/uuid.h"
#include "src/shared/util.h"
#include "src/shared/tester.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"
#include "src/shared/vcp.h"

struct test_data {
	struct gatt_db *db;
	struct bt_vcp  *bt_vcp;
	struct bt_gatt_server *server;
	struct queue *ccc_states;
	struct queue *device_states;
	struct queue *ccc_callbacks;
	size_t iovcnt;
	struct iovec *iov;
};

struct pending_op {
	struct bt_att *att;
	unsigned int id;
	unsigned int disconn_id;
	uint16_t offset;
	uint8_t link_type;
	struct gatt_db_attribute *attrib;
	struct queue *owner_queue;
	struct iovec data;
	bool is_characteristic;
	bool prep_authorize;
};

typedef uint8_t (*btd_gatt_database_ccc_write_t) (struct pending_op *op,
							void *user_data);
typedef void (*btd_gatt_database_destroy_t) (void *data);

struct ccc_state {
	uint16_t handle;
	uint16_t value;
};

struct ccc_cb_data {
	uint16_t handle;
	btd_gatt_database_ccc_write_t callback;
	btd_gatt_database_destroy_t destroy;
	void *user_data;
};

/* ATT: Exchange MTU Request (0x02) len 2
 *   Client RX MTU: 64
 * ATT: Exchange MTU Response (0x03) len 2
 *   Server RX MTU: 64
 */
#define EXCHANGE_MTU \
	IOV_DATA(0x02, 0x40, 0x00), \
	IOV_DATA(0x03, 0x40, 0x00)

/* ATT: Find By Type Value Request (0x06) len 8
 *   Handle range: 0x0001-0xffff
 *   Attribute Type(UUID): Primary Service (0x2800)
 *   Value to find: Volume Offset Control (0x1845)
 * ATT: Error Response (0x01) len 4
 * 	 Find By Type Value Request (0x06)
 *   Handle: 0x0001
 *   Error: Attribute Not Found (0x0a)
 * ATT: Find By Type Value Request (0x08) len 8
 *   Handle range: 0x0001-0xffff
 *   Attribute Type(UUID): Include Service (0x2802)
 * ATT: Find By Type Value Response (0x07) len 4
 *   Handle range: 0x0001-0x000c
 * ATT: Find By Type Value Request (0x08) len 8
 *   Handle range: 0x000f-0xffff
 *   Attribute Type(UUID): Include Service (0x2802)
 * ATT: Error Response (0x01) len 4
 *   Find By Type Value Request (0x08)
 *   Handle: 0x000f
 *   Error: Attribute Not Found (0x0a)
 */
#define VOCS_FIND_BY_TYPE_VALUE \
	IOV_DATA(0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x45, 0x18), \
	IOV_DATA(0x01, 0x06, 0x01, 0x00, 0x0a), \
	IOV_DATA(0x08, 0x01, 0x00, 0xff, 0xff, 0x02, 0x28), \
	IOV_DATA(0x09, 0x08, 0x0e, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x45, 0x18), \
	IOV_DATA(0x08, 0x0f, 0x00, 0xff, 0xff, 0x02, 0x28), \
	IOV_DATA(0x01, 0x08, 0x0f, 0x00, 0x0a)

/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0001-0x000c
 *   Attribute type: Characteristic (0x2803)
 * ATT: Read By Type Response (0x09) len 22
 * Attribute data length: 7
 * Attribute data list: 3 entries
 *   Handle: 0x0002
 *   Value: 120300802b
 *   Properties: 0x12
 *     Read (0x02)
 *     Notify (0x10)
 *   Value Handle: 0x0003
 *   Value UUID: Offset State (0x2b80)
 *   Handle: 0x0005
 *   Value: 120600812b
 *   Properties: 0x12
 *     Read (0x02)
 *     Notify (0x10)
 *   Value Handle: 0x0006
 *   Value UUID: Audio Location (0x2b81)
 *   Handle: 0x0008
 *   Value: 080900822b
 *   Properties: 0x0c
 *     Write (0x08)
 *   Value Handle: 0x0009
 *   Value UUID: Volume Offset Control Point (0x2b82)
 *   Handle: 0x000a
 *   Value: 120b00832b
 *   Properties: 0x0c
 *     Write (0x08)
 *   Value Handle: 0x0009
 *   Value UUID: Audio Output Description (0x2b83)
 * ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x000c-0x000c
 *   Attribute type: Characteristic (0x2803)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x000c
 *   Error: Attribute Not Found (0x0a)
 */
/*#define DISC_VOCS_CHAR \
	IOV_DATA(0x08, 0x01, 0x00, 0x0c, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x02, 0x00, 0x12, 0x03, 0x00, 0x80, 0x2b, \
		0x05, 0x00, 0x12, 0x06, 0x00, 0x81, 0x2b, \
		0x08, 0x00, 0x08, 0x09, 0x00, 0x82, 0x2b, \
		0x0a, 0x00, 0x12, 0x0b, 0x00, 0x83, 0x2b), \
	IOV_DATA(0x08, 0x0c, 0x00, 0x0c, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x0c, 0x00, 0x0a)*/

#define DISC_OFFSET_STATE_CHAR \
	IOV_DATA(0x08, 0x02, 0x00, 0x02, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x02, 0x00, 0x12, 0x03, 0x00, 0x80, 0x2b), \
	IOV_DATA(0x08, 0x0c, 0x00, 0x0c, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x0c, 0x00, 0x0a)


/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0005-0x0005
 *   Attribute type: Characteristic (0x2803)
 * ATT: Read By Type Response (0x09) len 22
 * Attribute data length: 7
 * Attribute data list: 1 entries
 *   Handle: 0x0005
 *   Value: 120600812b
 *   Properties: 0x12
 *     Read (0x02)
 *     Notify (0x10)
 *   Value Handle: 0x0006
 *   Value UUID: Audio Location (0x2b81)
 * ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x000c-0x000c
 *   Attribute type: Characteristic (0x2803)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x000c
 *   Error: Attribute Not Found (0x0a)*/
#define DISC_AUDIO_LOC_CHAR \
	IOV_DATA(0x08, 0x05, 0x00, 0x05, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x05, 0x00, 0x12, 0x06, 0x00, 0x81, 0x2b), \
	IOV_DATA(0x08, 0x0c, 0x00, 0x0c, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x0c, 0x00, 0x0a)


/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x0008-0x0008
 *   Attribute type: Characteristic (0x2803)
 * ATT: Read By Type Response (0x09) len 22
 *   Handle: 0x0008
 *   Value: 080900822b
 *   Properties: 0x0c
 *     Write (0x08)
 *   Value Handle: 0x0009
 *   Value UUID: Volume Offset Control Point (0x2b82)
 * ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x000c-0x000c
 *   Attribute type: Characteristic (0x2803)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x000c
 *   Error: Attribute Not Found (0x0a)*/
#define DISC_VOL_OFFSET_CP_CHAR \
	IOV_DATA(0x08, 0x08, 0x00, 0x08, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x08, 0x00, 0x08, 0x09, 0x00, 0x82, 0x2b), \
	IOV_DATA(0x08, 0x0c, 0x00, 0x0c, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x0c, 0x00, 0x0a)

/* ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x000a-0x000a
 *   Attribute type: Characteristic (0x2803)
 * ATT: Read By Type Response (0x09) len 22
 *   Handle: 0x000a
 *   Value: 120b00832b
 *   Properties: 0x0c
 *     Write (0x08)
 *   Value Handle: 0x0009
 *   Value UUID: Audio Output Description (0x2b83)
 * ATT: Read By Type Request (0x08) len 6
 *   Handle range: 0x000c-0x000c
 *   Attribute type: Characteristic (0x2803)
 * ATT: Error Response (0x01) len 4
 *   Read By Type Request (0x08)
 *   Handle: 0x000c
 *   Error: Attribute Not Found (0x0a)*/
#define DISC_AUD_OP_DESC_CHAR \
	IOV_DATA(0x08, 0x0a, 0x00, 0x0a, 0x00, 0x03, 0x28), \
	IOV_DATA(0x09, 0x07, \
		0x0a, 0x00, 0x12, 0x0b, 0x00, 0x83, 0x2b),  \
	IOV_DATA(0x08, 0x0c, 0x00, 0x0c, 0x00, 0x03, 0x28), \
	IOV_DATA(0x01, 0x08, 0x0c, 0x00, 0x0a)

/* ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x0001-0xffff
 *   Attribute group type: Secondary Service (0x2801)
 * ATT: Read By Group Type Response (0x11) len 7
 *   Attribute data length: 6
 *   Attribute group list: 1 entry
 *   Handle range: 0x0001-0x000c
 *   UUID: Volume Offset Control (0x1845)
 * ATT: Read By Group Type Request (0x10) len 6
 *   Handle range: 0x000d-0xffff
 *   Attribute group type: Secondary Service (0x2800)
 * ATT: Error Response (0x01) len 4
 *   Read By Group Type Request (0x10)
 *   Handle: 0x000d
 *   Error: Attribute Not Found (0x0a)
 */
#define VOCS_SERVICE_READ \
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28), \
	IOV_DATA(0x11, 0x06, 0x01, 0x00, 0x0c, 0x00, 0x45, 0x18), \
	IOV_DATA(0x10, 0x0d, 0x00, 0xff, 0xff, 0x01, 0x28), \
	IOV_DATA(0x01, 0x10, 0x0d, 0x00, 0x0a)

#define VOCS_CP_INVALID_COUNTER_CHANGE \
	IOV_DATA(0x12, 0x09, 0x00, 0x01, 0x0a, 0x0a, 0x00), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0x80)

#define VOCS_CP_OPCODE_NOT_SUPPORTED \
	IOV_DATA(0x12, 0x09, 0x00, 0x02, 0x00, 0x01, 0x00), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0x81)

#define VOCS_CP_VALUE_OOR \
	IOV_DATA(0x12, 0x09, 0x00, 0x01, 0x00, 0x0e, 0x01), \
	IOV_DATA(0x01, 0x12, 0x09, 0x00, 0x82)

#define DISC_VOCS_OFFSET_STATE_CHAR \
	EXCHANGE_MTU,\
	VOCS_SERVICE_READ, \
	VOCS_FIND_BY_TYPE_VALUE, \
	DISC_OFFSET_STATE_CHAR

#define DISC_VOCS_AUD_LOC_CHAR \
	EXCHANGE_MTU,\
	VOCS_SERVICE_READ, \
	VOCS_FIND_BY_TYPE_VALUE, \
	DISC_AUDIO_LOC_CHAR

#define DISC_VOCS_OFFSET_CP_CHAR \
	EXCHANGE_MTU,\
	VOCS_SERVICE_READ, \
	VOCS_FIND_BY_TYPE_VALUE, \
	DISC_VOL_OFFSET_CP_CHAR

#define DISC_VOCS_AUD_OP_DESC_CHAR \
	EXCHANGE_MTU,\
	VOCS_SERVICE_READ, \
	VOCS_FIND_BY_TYPE_VALUE, \
	DISC_AUD_OP_DESC_CHAR

#define WRITE_VOCS_INVALID_COUNTER_CHANGE \
	VOCS_CP_INVALID_COUNTER_CHANGE

#define WRITE_VOCS_OPCODE_NOT_SUPPORTED \
	VOCS_CP_OPCODE_NOT_SUPPORTED

#define WRITE_VOCS_VALUE_OOR \
	VOCS_CP_VALUE_OOR


/*#define DISC_VOCS_AUDIO_LOC_SER \
	EXCHANGE_MTU,\
	IOV_DATA(0x10, 0x01, 0x00, 0xff, 0xff, 0x01, 0x28), \
	IOV_DATA(0x11, 0x06, 0x01, 0x00, 0x0c, 0x00, 0x45, 0x18), \
	IOV_DATA(0x10, 0x0d, 0x00, 0xff, 0xff, 0x01, 0x28), \
	IOV_DATA(0x01, 0x10, 0x0d, 0x00, 0x0a), \
	VOCS_FIND_BY_TYPE_VALUE, \
	DISC_OFFSET_STATE_CHAR*/


#define iov_data(args...) ((const struct iovec[]) { args })

#define define_test(name, function, _cfg, args...)		\
	do {							\
		const struct iovec iov[] = { args };		\
		static struct test_data data;			\
		data.iovcnt = ARRAY_SIZE(iov_data(args));	\
		data.iov = util_iov_dup(iov, ARRAY_SIZE(iov_data(args))); \
		tester_add(name, &data, NULL, function,	\
				test_teardown);			\
	} while (0)

static void test_complete_cb(const void *user_data)
{
	tester_test_passed();
}

static void print_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	if (tester_use_debug())
		tester_debug("%s%s", prefix, str);
}

static void test_teardown(const void *user_data)
{
	struct test_data *data = (void *)user_data;

	bt_vcp_unref(data->bt_vcp);
	bt_gatt_server_unref(data->server);
	util_iov_free(data->iov, data->iovcnt);

	gatt_db_unref(data->db);

	queue_destroy(data->ccc_states, free);

	tester_teardown_complete();
}

static bool ccc_state_match(const void *a, const void *b)
{
	const struct ccc_state *ccc = a;
	uint16_t handle = PTR_TO_UINT(b);

	return ccc->handle == handle;
}

static struct ccc_state *find_ccc_state(struct test_data *data,
				uint16_t handle)
{
	return queue_find(data->ccc_states, ccc_state_match,
				UINT_TO_PTR(handle));
}


static struct ccc_state *get_ccc_state(struct test_data *data, uint16_t handle)
{
	struct ccc_state *ccc;

	ccc = find_ccc_state(data, handle);
	if (ccc)
		return ccc;

	ccc = new0(struct ccc_state, 1);
	ccc->handle = handle;
	queue_push_tail(data->ccc_states, ccc);

	return ccc;
}

#if UNIT_WRITE
static struct ccc_state *get_ccc_state(struct test_data *database,
					struct bt_att *att, uint16_t handle)
{
	struct device_state *dev_state;
	struct ccc_state *ccc;

	dev_state = get_device_state(database, att);
	if (!dev_state)
		return NULL;

	ccc = find_ccc_state(dev_state, handle);
	if (ccc)
		return ccc;

	ccc = new0(struct ccc_state, 1);
	ccc->handle = handle;
	queue_push_tail(dev_state->ccc_states, ccc);

	return ccc;
}
#endif

static void gatt_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct test_data *data = user_data;
	struct ccc_state *ccc;
	uint16_t handle;
	uint8_t ecode = 0;
	const uint8_t *value = NULL;
	size_t len = 0;

	handle = gatt_db_attribute_get_handle(attrib);

	ccc = get_ccc_state(data, handle);
	if (!ccc) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	len = sizeof(ccc->value);
	value = (void *) &ccc->value;

done:
	gatt_db_attribute_read_result(attrib, id, ecode, value, len);
}

#if UNIT_WRITE
static bool ccc_cb_match_handle(const void *data, const void *match_data)
{
	const struct ccc_cb_data *ccc_cb = data;
	uint16_t handle = PTR_TO_UINT(match_data);

	return ccc_cb->handle == handle;
}


static void gatt_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct test_data *database = user_data;
	struct ccc_state *ccc;
	struct ccc_cb_data *ccc_cb;
	uint16_t handle, val;
	uint8_t ecode = 0;

	handle = gatt_db_attribute_get_handle(attrib);

	//DBG("CCC write called for handle: 0x%04x", handle);

	if (!value || len > 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset > 2) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	ccc = get_ccc_state(database, handle);
	if (!ccc) {
		ecode = BT_ATT_ERROR_UNLIKELY;
		goto done;
	}

	if (len == 1)
		val = *value;
	else
		val = get_le16(value);

	/* If value is identical, then just succeed */
	if (val == ccc->value)
		goto done;

	ccc_cb = queue_find(database->ccc_callbacks, ccc_cb_match_handle,
			UINT_TO_PTR(gatt_db_attribute_get_handle(attrib)));
	if (ccc_cb) {
		struct pending_op *op;

		op = pending_ccc_new(att, attrib, val,
					bt_att_get_link_type(att));
		if (!op) {
			ecode = BT_ATT_ERROR_UNLIKELY;
			goto done;
		}

		ecode = ccc_cb->callback(op, ccc_cb->SS);
		if (ecode)
			pending_op_free(op);
	}

	if (!ecode)
		ccc->value = val;

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}
#endif

static void test_server(const void *user_data)
{
	struct test_data *data = (void *)user_data;
	struct bt_att *att;
	struct io *io;

	io = tester_setup_io(data->iov, data->iovcnt);
	g_assert(io);

	tester_io_set_complete_func(test_complete_cb);

	att = bt_att_new(io_get_fd(io), false);
	g_assert(att);

	bt_att_set_debug(att, BT_ATT_DEBUG, print_debug, "bt_att:", NULL);

	data->db = gatt_db_new();
	g_assert(data->db);

	gatt_db_ccc_register(data->db, gatt_ccc_read_cb, NULL,
					NULL, data);

	data->bt_vcp = bt_vcp_new(data->db, NULL);
	g_assert(data->bt_vcp);

	data->server = bt_gatt_server_new(data->db, att, 64, 0);
	g_assert(data->server);

	bt_gatt_server_set_debug(data->server, print_debug, "bt_gatt_server:",
						NULL);

	data->ccc_states = queue_new();

	tester_io_send();

	bt_att_unref(att);
}

static void test_sggit(void)
{
	define_test("VOCS/SR/SGGIT/CHA/BV-01-C", test_server, NULL,
							DISC_VOCS_OFFSET_STATE_CHAR);

	define_test("VOCS/SR/SGGIT/CHA/BV-02-C", test_server, NULL,
							DISC_VOCS_AUD_LOC_CHAR);

	define_test("VOCS/SR/SGGIT/CHA/BV-03-C", test_server, NULL,
							DISC_VOCS_OFFSET_CP_CHAR);

	define_test("VOCS/SR/SGGIT/CHA/BV-04-C", test_server, NULL,
							DISC_VOCS_AUD_OP_DESC_CHAR);

	define_test("VOCS/SR/SGGIT/CP/BI-01-C", test_server, NULL,
							WRITE_VOCS_INVALID_COUNTER_CHANGE);

	define_test("VOCS/SR/SGGIT/CP/BI-02-C", test_server, NULL,
							WRITE_VOCS_OPCODE_NOT_SUPPORTED);

	define_test("VOCS/SR/SGGIT/CP/BI-03-C", test_server, NULL,
							WRITE_VOCS_VALUE_OOR);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_sggit();

	return tester_run();
}
