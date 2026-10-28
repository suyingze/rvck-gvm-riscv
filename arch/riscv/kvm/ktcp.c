/*
 * TCP support for KVM software distributed memory
 *
 * This feature allows us to run multiple KVM instances on different machines
 * sharing the same address space.
 *
 * Copyright (C) 2019, Trusted Cloud Group, Shanghai Jiao Tong University.
 *
 * Authors:
 *   Yubin Chen <binsschen@sjtu.edu.cn>
 *   Zhuocheng Ding <tcbbd@sjtu.edu.cn>
 *   Jin Zhang <jzhang3002@sjtu.edu.cn>
 *   Boshi Yu <201608ybs@sjtu.edu.cn>
 *   Tianlei Xiong <qmyyxtl@sjtu.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kvm_host.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

#include "ktcp.h"

#define KTCP_RECV_BUF_SIZE 32

struct ktcp_hdr {
	size_t length;
	tx_add_t tx_add;
} __attribute__((packed));

typedef struct ktcp_msg
{
	uint32_t txid;
	void *recv_buf;
} ktcp_msg_t;

struct ktcp_cb
{
	struct mutex slock;
	struct mutex rlock;
	ktcp_msg_t recv_trans_buf[KTCP_RECV_BUF_SIZE];
	struct socket *socket;
};

#define KTCP_BUFFER_SIZE (sizeof(struct ktcp_hdr) + PAGE_SIZE)

static inline bool ktcp_current_should_stop(void)
{
	return (current->flags & PF_KTHREAD) && kthread_should_stop();
}

static int __ktcp_send(struct socket *sock, const char *buffer, size_t length,
		unsigned long flags)
{
	struct kvec vec;
	int len, written = 0, left = length;
	int ret;
	// printk("gvmdebug %s(%s:%d): with header length: %llu buffer content: %02x %02x %02x %02x %02x %02x %02x %02x\n",
	// 	__func__, __FILE__, __LINE__, (u64)length,
	// 	buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]);
	struct msghdr msg = {
		.msg_name    = 0,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags   = flags,
	};

repeat_send:
	vec.iov_len = left;
	vec.iov_base = (char *)buffer + written;

	len = kernel_sendmsg(sock, &msg, &vec, 1, left);
	if (len == -EAGAIN || len == -ERESTARTSYS) {
		if (fatal_signal_pending(current))
			return -ERESTARTSYS;
		cond_resched();
		usleep_range(1, 10);
		goto repeat_send;
	}
	if (len > 0) {
		written += len;
		left -= len;
		if (left != 0) {
			goto repeat_send;
		}
	}

	ret = written != 0 ? written : len;
	// if (ret > 0 && ret != length) {
	// 	printk("gvmdebug ktcp_send send %d bytes which expected_size=%lu bytes", ret, length);
	// }

	// if (ret < 0) {
	// 	printk(KERN_ERR "gvmdebug ktcp_send %d", ret);
	// }
	// printk("gvmdebug ktcp_send send %d bytes which expected_size=%lu bytes", ret, length);
	return ret;
}

int ktcp_send(struct ktcp_cb *cb, const char *buffer, size_t length,
		unsigned long flags, const tx_add_t *tx_add)
{
	int ret;
	struct ktcp_hdr hdr;
	char *local_buffer;
	mutex_lock(&cb->slock);
	hdr.tx_add = *tx_add;
	hdr.length = sizeof(hdr) + length;
	if (length > PAGE_SIZE) {
		printk(KERN_ERR "%s: ktcp payload too large, length %zu\n",
		       __func__, length);
		mutex_unlock(&cb->slock);
		return -EMSGSIZE;
	}

	local_buffer = kzalloc(hdr.length, GFP_KERNEL);
	if (!local_buffer) {
		mutex_unlock(&cb->slock);
		return -ENOMEM;
	}
	memcpy(local_buffer, &hdr, sizeof(hdr));
	memcpy(local_buffer + sizeof(hdr), buffer, length);
	ret = __ktcp_send(cb->socket, local_buffer, hdr.length, flags);
	if (ret < 0)
		goto out;

out:
	kfree(local_buffer);
	mutex_unlock(&cb->slock);
	return ret < 0 ? ret : hdr.length;
}

static bool search_recv_buf(struct ktcp_cb *cb, uint32_t txid, ktcp_msg_t *msg)
{
	int i;

	for(i = 0; i < KTCP_RECV_BUF_SIZE; ++i)
	{
		if ((txid == DSM_TXID_ANY || cb->recv_trans_buf[i].txid == txid) &&
		    cb->recv_trans_buf[i].recv_buf != NULL) {
				*msg = cb->recv_trans_buf[i];
				cb->recv_trans_buf[i].txid = 0;
				cb->recv_trans_buf[i].recv_buf = NULL;
				return true;
		}
	}
	return false;
}

static bool insert_into_recv_buf(struct ktcp_cb *cb, ktcp_msg_t msg)
{
	int i;

	for(i = 0; i < KTCP_RECV_BUF_SIZE; ++i)
	{
		if (cb->recv_trans_buf[i].txid == 0 && cb->recv_trans_buf[i].recv_buf == NULL) {
				cb->recv_trans_buf[i] = msg;
				return true;
		}
	}

	return false;
}

static int build_ktcp_recv_output(ktcp_msg_t msg, char *buffer, size_t buffer_len, tx_add_t *tx_add)
{
	size_t real_length;
	struct ktcp_hdr hdr;

	if (!msg.recv_buf)
		return -EINVAL;

	memcpy(&hdr, (char *)msg.recv_buf, sizeof(struct ktcp_hdr));
	if (hdr.length < sizeof(struct ktcp_hdr) ||
	    hdr.length > KTCP_BUFFER_SIZE) {
		printk(KERN_ERR "%s: invalid ktcp message length %zu\n",
		       __func__, hdr.length);
		kfree(msg.recv_buf);
		return -EINVAL;
	}

	real_length = hdr.length - sizeof(struct ktcp_hdr);
	if (real_length > buffer_len) {
		printk(KERN_ERR
		       "%s: ktcp payload length %zu exceeds caller buffer %zu txid=0x%x\n",
		       __func__, real_length, buffer_len, hdr.tx_add.txid);
		kfree(msg.recv_buf);
		return -EMSGSIZE;
	}

	memcpy(buffer, (char *)msg.recv_buf + sizeof(struct ktcp_hdr), real_length);
	*tx_add = hdr.tx_add;
	kfree(msg.recv_buf);
	return real_length;
}

static int __ktcp_receive(struct socket *sock, char *buffer, size_t expected_size,
		unsigned long flags)
{
	struct kvec vec;
	int ret;
	int len = 0;

	struct msghdr msg = {
		.msg_name    = 0,
		.msg_namelen = 0,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags   = MSG_DONTWAIT,
	};

	if (expected_size == 0) {
		return 0;
	}

read_again:
	if (fatal_signal_pending(current) || ktcp_current_should_stop())
		return -ERESTARTSYS;

	vec.iov_len = expected_size - len;
	vec.iov_base = buffer + len;
	ret = kernel_recvmsg(sock, &msg, &vec, 1, expected_size - len, MSG_DONTWAIT);

	if (ret == 0) {
		return len;
	}

	// Non-blocking on the first try
	if (len == 0 && (flags & SOCK_NONBLOCK) &&
			(ret == -EWOULDBLOCK || ret == -EAGAIN)) {
		return ret;
	}

		if (ret == -EAGAIN || ret == -EWOULDBLOCK || ret == -ERESTARTSYS) {
			if (len == 0 && (flags & SOCK_NONBLOCK))
				return ret;
			if (fatal_signal_pending(current) || ktcp_current_should_stop())
				return -ERESTARTSYS;
			cond_resched();
			usleep_range(1, 10);
			goto read_again;
		}
	else if (ret < 0) {
		if (ret != -ECONNRESET)
			printk(KERN_ERR "kernel_recvmsg %d\n", ret);
		return ret;
	}
	len += ret;
	if (len != expected_size) {
		cond_resched();
		usleep_range(1, 10);
		goto read_again;
	}

	return len;
}

int ktcp_receive(struct ktcp_cb *cb, char *buffer, size_t buffer_len, unsigned long flags,
		tx_add_t *tx_add)
{
	struct ktcp_hdr hdr;
	int ret;
	ktcp_msg_t msg;
	uint32_t usec_sleep = 0;
	char *local_buffer;

	BUG_ON(cb == NULL || buffer == NULL || tx_add == NULL);

	if (mutex_lock_interruptible(&cb->rlock))
		return -ERESTARTSYS;
repoll:
	if (fatal_signal_pending(current) || ktcp_current_should_stop()) {
		ret = -ERESTARTSYS;
		goto out;
	}

	if (search_recv_buf(cb, tx_add->txid, &msg)){
		ret = build_ktcp_recv_output(msg, buffer, buffer_len, tx_add);
		mutex_unlock(&cb->rlock);
		return ret;
	}
	local_buffer = kzalloc(KTCP_BUFFER_SIZE, GFP_KERNEL);
	if (!local_buffer) {
		ret = -ENOMEM;
		goto out;
	}
	ret = __ktcp_receive(cb->socket, local_buffer, sizeof(hdr), flags);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			mutex_unlock(&cb->rlock);
			usec_sleep = (usec_sleep + 1) > 1000 ? 1000 : (usec_sleep + 1);
			usleep_range(usec_sleep, usec_sleep);
			cond_resched();
			if (mutex_lock_interruptible(&cb->rlock)) {
				kfree(local_buffer);
				return -ERESTARTSYS;
			}
			kfree(local_buffer);
			goto repoll;
		}
		kfree(local_buffer);
		if (ret != -ERESTARTSYS && ret != -ECONNRESET)
			printk(KERN_ERR "%s: __ktcp_receive header error, ret %d\n",
					__func__, ret);
		goto out;
	}
	if (ret != sizeof(hdr)) {
		kfree(local_buffer);
		ret = ret ? -EIO : -ECONNRESET;
		if (ret != -ECONNRESET)
			printk(KERN_ERR "%s: short ktcp header receive, ret %d\n",
			       __func__, ret);
		goto out;
	}
	usec_sleep = 0;
	memcpy(&hdr, local_buffer, sizeof(hdr));
	if (hdr.length < sizeof(hdr) || hdr.length > KTCP_BUFFER_SIZE) {
		kfree(local_buffer);
		ret = -EINVAL;
		printk(KERN_ERR "%s: invalid ktcp header length %zu\n",
		       __func__, hdr.length);
		goto out;
	}
	if (hdr.length > sizeof(hdr)) {
		ret = __ktcp_receive(cb->socket,
				     local_buffer + sizeof(hdr),
				     hdr.length - sizeof(hdr), 0);
		if (ret != hdr.length - sizeof(hdr)) {
			kfree(local_buffer);
			ret = ret < 0 ? ret : -EIO;
			if (ret != -ERESTARTSYS && ret != -ECONNRESET)
				printk(KERN_ERR "%s: ktcp payload receive error, ret %d expected %zu\n",
				       __func__, ret, hdr.length - sizeof(hdr));
			goto out;
		}
	}
	msg.recv_buf = local_buffer;
	msg.txid = hdr.tx_add.txid;
	if (hdr.tx_add.txid != tx_add->txid && tx_add->txid != DSM_TXID_ANY){
		while(!insert_into_recv_buf(cb, msg)){
			mutex_unlock(&cb->rlock);
			usec_sleep = (usec_sleep + 1) > 1000 ? 1000 : (usec_sleep + 1);
			usleep_range(usec_sleep, usec_sleep);
			cond_resched();
			if (mutex_lock_interruptible(&cb->rlock)) {
				kfree(local_buffer);
				return -ERESTARTSYS;
			}
		}
		usec_sleep = 0;
		goto repoll;
	}
	else{
		ret = build_ktcp_recv_output(msg, buffer, buffer_len, tx_add);
		if (ret < 0)
			goto out;
	}
out:
	mutex_unlock(&cb->rlock);
	return ret;
}

static int ktcp_create_cb(struct ktcp_cb **cbp)
{
	struct ktcp_cb *cb;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;

	mutex_init(&cb->slock);
	mutex_init(&cb->rlock);

	*cbp = cb;
	return 0;
}

static void ktcp_free_cb(struct ktcp_cb *cb)
{
	int i;

	if (!cb)
		return;

	for (i = 0; i < KTCP_RECV_BUF_SIZE; ++i) {
		kfree(cb->recv_trans_buf[i].recv_buf);
		cb->recv_trans_buf[i].recv_buf = NULL;
		cb->recv_trans_buf[i].txid = 0;
	}

	kfree(cb);
}

int ktcp_connect(const char *host, const char *port, struct ktcp_cb **conn_cb)
{
	int ret;
	struct sockaddr_in saddr;
	long portdec;
	struct ktcp_cb *cb;
	struct socket *conn_socket;

	if (host == NULL || port == NULL || conn_cb == NULL) {
		return -EINVAL;
	}

	ret = ktcp_create_cb(&cb);
	if (ret < 0) {
		printk(KERN_ERR "%s: ktcp_create_cb fail, return %d\n",
				__func__, ret);
		return ret;
	}

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_socket);
	if (ret < 0) {
		printk(KERN_ERR "%s: sock_create failed, return %d\n", __func__, ret);
		ktcp_free_cb(cb);
		return ret;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	BUG_ON(kstrtol(port, 10, &portdec) != 0);
	saddr.sin_port = htons(portdec);
	saddr.sin_addr.s_addr = in_aton(host);

re_connect:
	ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&saddr,
			sizeof(saddr), O_RDWR);
	if (ret == -EAGAIN || ret == -ERESTARTSYS) {
		goto re_connect;
	}

	if (ret && (ret != -EINPROGRESS)) {
		printk(KERN_ERR "%s: connct failed, return %d\n", __func__, ret);
		sock_release(conn_socket);
		ktcp_free_cb(cb);
		return ret;
	}

	cb->socket = conn_socket;
	mutex_init(&cb->slock);
	mutex_init(&cb->rlock);
	*conn_cb = cb;
	return SUCCESS;
}

int ktcp_listen(const char *host, const char *port, struct ktcp_cb **listen_cb)
{
	int ret;
	struct sockaddr_in saddr;
	long portdec;
	struct ktcp_cb *cb;
	struct socket *listen_socket;

	ret = ktcp_create_cb(&cb);
	if (ret < 0) {
		printk(KERN_ERR "%s: ktcp_create_cb failed, return %d\n",
				__func__, ret);
		return ret;
	}

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_socket);
	if (ret != 0) {
		printk(KERN_ERR "%s: sock_create failed, return %d\n", __func__, ret);
		ktcp_free_cb(cb);
		return ret;
	}

	/*
	 * DSM VMs are often restarted back-to-back during bring-up. Reusing
	 * the listener address avoids bind failures while the previous TCP
	 * connection is still in TIME_WAIT on localhost.
	 */
	sock_set_reuseaddr(listen_socket->sk);

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	BUG_ON(kstrtol(port, 10, &portdec) != 0);
	saddr.sin_port = htons(portdec);
	saddr.sin_addr.s_addr = in_aton(host);

	ret = listen_socket->ops->bind(listen_socket, (struct sockaddr *)&saddr, sizeof(saddr));
	if (ret != 0) {
		printk(KERN_ERR "%s: bind failed, return %d\n", __func__, ret);
		sock_release(listen_socket);
		ktcp_free_cb(cb);
		return ret;
	}

	ret = listen_socket->ops->listen(listen_socket, DEFAULT_BACKLOG);
	if (ret != 0) {
		printk(KERN_ERR "%s: listen failed, return %d\n", __func__, ret);
		sock_release(listen_socket);
		ktcp_free_cb(cb);
		return ret;
	}

	cb->socket = listen_socket;
	*listen_cb = cb;
	return SUCCESS;
}

int ktcp_accept(struct ktcp_cb *listen_cb, struct ktcp_cb **accept_cb, unsigned long flag)
{
	int ret;
	struct ktcp_cb *cb;
	struct socket *listen_socket, *accept_socket;

	if (listen_cb == NULL || (listen_socket = listen_cb->socket) == NULL) {
		printk(KERN_ERR "%s: null listen_cb\n", __func__);
		return -EINVAL;
	}

	ret = ktcp_create_cb(&cb);
	if (ret < 0) {
		printk(KERN_ERR "%s: ktcp_create_cb failed, return %d\n",
				__func__, ret);
		return ret;
	}

	ret = sock_create_lite(listen_socket->sk->sk_family, listen_socket->sk->sk_type,
			listen_socket->sk->sk_protocol, &accept_socket);
	if (ret != 0) {
		printk(KERN_ERR "%s: sock_create failed, return %d\n", __func__, ret);
		ktcp_free_cb(cb);
		return ret;
	}

re_accept:
	ret = listen_socket->ops->accept(listen_socket, accept_socket, flag,0);
	if (ret == -ERESTARTSYS) {
		if (ktcp_current_should_stop()) {
			sock_release(accept_socket);
			ktcp_free_cb(cb);
			return ret;
		}
		goto re_accept;
	}
	// When setting SOCK_NONBLOCK flag, accept return this when there's nothing in waiting queue.
	if (ret == -EWOULDBLOCK || ret == -EAGAIN) {
		sock_release(accept_socket);
		accept_socket = NULL;
		ktcp_free_cb(cb);
		return ret;
	}
	if (ret < 0) {
		printk(KERN_ERR "%s: accept failed, return %d\n", __func__, ret);
		sock_release(accept_socket);
		accept_socket = NULL;
		ktcp_free_cb(cb);
		return ret;
	}

	accept_socket->ops = listen_socket->ops;
	cb->socket = accept_socket;
	mutex_init(&cb->slock);
	mutex_init(&cb->rlock);
	*accept_cb = cb;
	return SUCCESS;
}

int ktcp_shutdown(struct ktcp_cb *conn_cb)
{
	if (conn_cb == NULL || conn_cb->socket == NULL)
		return -EINVAL;

	kernel_sock_shutdown(conn_cb->socket, SHUT_RDWR);
	return SUCCESS;
}

int ktcp_release(struct ktcp_cb *conn_cb)
{
	if (conn_cb == NULL) {
		return -EINVAL;
	}

	if (conn_cb->socket) {
		kernel_sock_shutdown(conn_cb->socket, SHUT_RDWR);
		sock_release(conn_cb->socket);
		conn_cb->socket = NULL;
	}

	ktcp_free_cb(conn_cb);
	return SUCCESS;
}
