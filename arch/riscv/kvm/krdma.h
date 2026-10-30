#ifndef __KVM_RISCV_KRDMA_H
#define __KVM_RISCV_KRDMA_H

#include <linux/pci.h>
#include <linux/list.h>
#include <linux/mm_types.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

#include "dsm-types.h"

#define RDMA_RESOLVE_TIMEOUT 2000
#define RDMA_CONNECT_RETRY_MAX 3

#define RDMA_SEND_QUEUE_DEPTH 4
#define RDMA_RECV_QUEUE_DEPTH 16
#define RDMA_CQ_QUEUE_DEPTH (RDMA_SEND_QUEUE_DEPTH + RDMA_RECV_QUEUE_DEPTH)

#define RDMA_SEND_BUF_SIZE RDMA_SEND_QUEUE_DEPTH
#define RDMA_RECV_BUF_SIZE RDMA_RECV_QUEUE_DEPTH

#define RDMA_SEND_BUF_LEN (PAGE_SIZE * 1024)
#define RDMA_RECV_BUF_LEN (PAGE_SIZE * 1024)

typedef uint32_t imm_t;

struct krdma_cb;

enum krdma_role {
	KRDMA_CLIENT_CONN = 0,
	KRDMA_LISTEN_CONN = 1,
	KRDMA_ACCEPT_CONN = 2,
};

enum krdma_code {
	SERVER_EXIT = 1000,
	CLIENT_EXIT,
	CLIENT_RETRY,
	STATE_ERROR,
};

void krdma_config(size_t max_buf_size);

int krdma_send(struct krdma_cb *cb, const char *buffer, size_t length,
		unsigned long flag, const tx_add_t *tx_add);

int krdma_receive(struct krdma_cb *cb, char *buffer, size_t buffer_len, unsigned long flag,
		tx_add_t *tx_add);

/* Direct-write data plane.  Control messages still use krdma_send/receive. */
int krdma_write(struct krdma_cb *cb, const char *buffer, size_t length,
		u64 remote_addr, u32 rkey);
int krdma_map_remote_page(struct krdma_cb *cb, struct page *page,
		u64 *remote_addr, u32 *rkey);
void krdma_unmap_remote_page(struct krdma_cb *cb, struct page *page,
		u64 remote_addr);
void krdma_sync_remote_page_for_device(struct krdma_cb *cb, u64 remote_addr);
void krdma_sync_remote_page_for_cpu(struct krdma_cb *cb, u64 remote_addr);

int krdma_connect(const char *host, const char *port, struct krdma_cb **conn_cb);

int krdma_listen(const char *host, const char *port, struct krdma_cb **listen_cb);

int krdma_accept(struct krdma_cb *listen_cb, struct krdma_cb **accept_cb, unsigned long flag);

int krdma_shutdown(struct krdma_cb *cb);

int krdma_release(struct krdma_cb *cb);

#endif /* __KVM_RISCV_KRDMA_H */
