/*
 * Longhorn backing store routine
 *
 * Copyright (C) 2016 Sheng Yang <sheng.yang@rancher.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <pthread.h>
#include <limits.h>
#include <ctype.h>
#include <sys/un.h>

#include "list.h"
#include "tgtd.h"
#include "util.h"
#include "log.h"
#include "scsi.h"
#include "bs_thread.h"

#include "liblonghorn.h"

struct longhorn_info {
	struct lh_client_conn *conn;
	size_t size;
	char *path;

	pthread_rwlock_t rwlock;
};

#define LHP(lu)	((struct longhorn_info *) \
			((char *)lu + \
			 sizeof(struct scsi_lu) + \
			 sizeof(struct bs_thread_info)) \
                )

static void set_medium_error(int *result, uint8_t *key, uint16_t *asc)
{
	*result = SAM_STAT_CHECK_CONDITION;
	*key = MEDIUM_ERROR;
	*asc = ASC_READ_ERROR;
}

static void bs_longhorn_request(struct scsi_cmd *cmd)
{
	int ret = 0;
	uint32_t length = 0;
	int result = SAM_STAT_GOOD;
	uint8_t key = 0;
	uint16_t asc = 0;
	struct longhorn_info *lh = LHP(cmd->dev);
	struct lh_client_conn *old_conn, *new_conn;

	switch (cmd->scb[0]) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
		length = scsi_get_out_length(cmd);
		pthread_rwlock_rdlock(&lh->rwlock);
		ret = lh_client_write_at(lh->conn, scsi_get_out_buffer(cmd),
			    length, cmd->offset);
		pthread_rwlock_unlock(&lh->rwlock);
		if (ret) {
                        eprintf("fail to write at %lx for %u\n", cmd->offset, length);
			set_medium_error(&result, &key, &asc);
                }
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		length = scsi_get_in_length(cmd);
		pthread_rwlock_rdlock(&lh->rwlock);
		ret = lh_client_read_at(lh->conn, scsi_get_in_buffer(cmd),
			    length, cmd->offset);
		pthread_rwlock_unlock(&lh->rwlock);
		if (ret) {
                        eprintf("fail to read at %lx for %u\n", cmd->offset, length);
			set_medium_error(&result, &key, &asc);
                }
		break;
	case EXCHANGE_MEDIUM:
		old_conn = lh->conn;
		new_conn = lh_client_allocate_conn();
		if (new_conn == NULL) {
			eprintf("cannot allocate new connection\n");
			set_medium_error(&result, &key, &asc);
			break;
		}

		ret = lh_client_open_conn(new_conn, lh->path);
		if (ret < 0) {
			eprintf("cannot refresh connection to %s: %d\n", lh->path, ret);
			set_medium_error(&result, &key, &asc);
			break;
		}
		eprintf("reconnected to %s\n", lh->path);

		pthread_rwlock_wrlock(&lh->rwlock);
		// no on-the-fly request after this point due to the lock
		lh->conn = new_conn;
		pthread_rwlock_unlock(&lh->rwlock);

		eprintf("connection updated, close old longhorn connection\n");
		lh_client_close_conn(old_conn);
		lh_client_free_conn(old_conn);
		break;
	default:
		eprintf("cmd->scb[0]: %x\n", cmd->scb[0]);
		break;
	}

	dprintf("io done %p %x %d %u\n", cmd, cmd->scb[0], ret, length);

	scsi_set_result(cmd, result);

	if (result != SAM_STAT_GOOD) {
		eprintf("io error %p %x %d %d %" PRIu64 ", %m\n",
			cmd, cmd->scb[0], ret, length, cmd->offset);
		sense_data_build(cmd, key, asc);
	}
}

static int bs_longhorn_open(struct scsi_lu *lu, char *path,
			    int *fd, uint64_t *size)
{
	struct longhorn_info *lh = LHP(lu);
	int rc;
	int len;

        rc = lh_client_open_conn(lh->conn, path);
	if (rc < 0) {
		eprintf("Cannot estibalish connection\n");
		return rc;
	}

	*size = lh->size;

	len = strlen(path);
	lh->path = malloc(len + 1); // ending '\0'
	strcpy(lh->path, path);

	return 0;
}

static void bs_longhorn_close(struct scsi_lu *lu)
{
	if (LHP(lu)->conn) {
                dprintf("close longhorn connection\n");
		lh_client_close_conn(LHP(lu)->conn);
	}
}

static char *slurp_to_semi(char **p)
{
	char *end = index(*p, ';');
	char *ret;
	int len;

	if (end == NULL)
		end = *p + strlen(*p);
	len = end - *p;
	ret = malloc(len + 1);
	strncpy(ret, *p, len);
	ret[len] = '\0';
	*p = end;
	/* Jump past the semicolon, if we stopped at one */
	if (**p == ';')
		*p = end + 1;
	return ret;
}

static char *slurp_value(char **p)
{
	char *equal = index(*p, '=');
	if (equal) {
		*p = equal + 1;
		return slurp_to_semi(p);
	} else {
		return NULL;
	}
}

static int is_opt(const char *opt, char *p)
{
	int ret = 0;
	if ((strncmp(p, opt, strlen(opt)) == 0) &&
		(p[strlen(opt)] == '=')) {
		ret = 1;
	}
	return ret;
}

static tgtadm_err bs_longhorn_init(struct scsi_lu *lu, char *bsopts)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);
	char *ssize = NULL;
	size_t size = 0;
        struct longhorn_info *lh = LHP(lu);
	int rc = 0;

	while (bsopts && strlen(bsopts)) {
		if (is_opt("size", bsopts)) {
			ssize = slurp_value(&bsopts);
			size = atoll(ssize);
		}
	}

	lh->conn = lh_client_allocate_conn();
	if (lh->conn == NULL) {
		perror("Cannot allocate connection\n");
		return TGTADM_NOMEM;
	}

	rc = pthread_rwlock_init(&lh->rwlock, NULL);
	if (rc < 0) {
		perror("Cannot init rwlock for connection\n");
		return TGTADM_NOMEM;
	}
	lh->size = size;
	return bs_thread_open(info, bs_longhorn_request, nr_iothreads);
}

static void bs_longhorn_exit(struct scsi_lu *lu)
{
	struct bs_thread_info *info = BS_THREAD_I(lu);
	struct longhorn_info *lh = LHP(lu);

	bs_thread_close(info);

	lh_client_free_conn(lh->conn);
	lh->conn = NULL;
	free(lh->path);
	pthread_rwlock_destroy(&lh->rwlock);
}

static struct backingstore_template longhorn_bst = {
	.bs_name		= "longhorn",
	.bs_datasize		= sizeof(struct bs_thread_info) +
					sizeof(struct longhorn_info),
	.bs_open		= bs_longhorn_open,
	.bs_close		= bs_longhorn_close,
	.bs_init		= bs_longhorn_init,
	.bs_exit		= bs_longhorn_exit,
	.bs_cmd_submit		= bs_thread_cmd_submit,
	.bs_oflags_supported    = O_SYNC | O_DIRECT | O_RDWR,
};

__attribute__((constructor)) void register_bs_module(void)
{
	unsigned char opcodes[] = {
		ALLOW_MEDIUM_REMOVAL,
		FORMAT_UNIT,
		INQUIRY,
		MAINT_PROTOCOL_IN,
		MODE_SELECT,
		MODE_SELECT_10,
		MODE_SENSE,
		MODE_SENSE_10,
		PERSISTENT_RESERVE_IN,
		PERSISTENT_RESERVE_OUT,
		READ_10,
		READ_12,
		READ_16,
		READ_6,
		READ_CAPACITY,
		RELEASE,
		REPORT_LUNS,
		REQUEST_SENSE,
		RESERVE,
		SEND_DIAGNOSTIC,
		SERVICE_ACTION_IN,
		START_STOP,
		SYNCHRONIZE_CACHE,
		SYNCHRONIZE_CACHE_16,
		TEST_UNIT_READY,
		WRITE_10,
		WRITE_12,
		WRITE_16,
		WRITE_6,
		EXCHANGE_MEDIUM,
	};

	bs_create_opcode_map(&longhorn_bst, opcodes, ARRAY_SIZE(opcodes));

	register_backingstore_template(&longhorn_bst);
}
