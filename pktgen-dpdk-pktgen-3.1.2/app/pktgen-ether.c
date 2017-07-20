/*-
 * Copyright (c) <2010>, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * - Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * Copyright (c) <2010-2014>, Wind River Systems, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 *
 * 3) Neither the name of Wind River Systems nor the names of its contributors may be
 * used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * 4) The screens displayed by the application must contain the copyright notice as defined
 * above and can not be removed without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* Created 2010 by Keith Wiles @ intel.com */

#include "pktgen-ether.h"
#include "pktgen-seq.h"
#include "pktgen-port-cfg.h"

#include "rte_cycles.h"

#include <sys/types.h>

/* these two are for unix time nsec now */
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>

/**************************************************************************//**
 *
 * pktgen_ether_hdr_ctor - Ethernet header constructor routine.
 *
 * DESCRIPTION
 * Construct the ethernet header for a given packet buffer.
 *
 * RETURNS: Pointer to memory after the ethernet header.
 *
 * SEE ALSO:
 */


#ifdef ENABLESYSCALL

#define NANOSECS    (1000000000)
#define CONVERSION ( 1 / 10)
#define SECONDS ( NANOSECS * CONVERSION )
inline uint32_t unix_time_now_nsec(void);
inline uint32_t unix_time_now_nsec(void){
    struct timespec ts;
    syscall (SYS_clock_gettime, CLOCK_REALTIME, &ts);
    /*struct timeval ts;        //We decided to avoid gettimeofday
    gettimeofday(&ts, NULL);*/
    //printf("S: %lu, NS/10: %lu TS: %u\n", ((ts.tv_sec & 0x1f)<<27),  (ts.tv_nsec/10), (uint32_t)( ((ts.tv_sec & 0x1f )<<27) +  (ts.tv_nsec/10) ) );
    //return 1e6 * ts.tv_sec + ts.tv_usec;    //Microseconds precision
    //return   ( ts.tv_sec & 0x1f )*SECONDS + (ts.tv_nsec*CONVERSION)  ;    // 10s Nanoseconds precision
    return (uint32_t)( ((ts.tv_sec & 0x1f )<<27) +  (ts.tv_nsec/10) );

}

#endif

uint32_t get_ts(void);
inline uint32_t get_ts(void){

    uint32_t lo, hi, ts;
    asm volatile("rdtsc" :
             "=a" (lo),
             "=d" (hi));
    ts = ( (lo>>5) & 0x7ffffff ) + ((hi & 0x1f) << 27 );

    //printf ("NEWLO: %u, NEWHi: %u, ||| TS: %u TS-old: %u\n", (lo>>5) & 0x7ffffff  , (hi & 0x1f) << 27  , ts, ts-old_ts);
    return ts;
    //return unix_time_now_usec();
    //return (uint32_t)( rte_rdtsc_precise() & 0xffffffff );
}

char *
pktgen_ether_hdr_ctor(port_info_t *info, pkt_seq_t *pkt, struct ether_hdr *eth)
{
	uint32_t flags;

	/* src and dest addr */
	//ether_addr_copy(&pkt->eth_src_addr, &eth->s_addr);

	//Leonardo, overwriting the source address, inverted order
	uint32_t ts = get_ts();
	uint8_t *pt = (uint8_t*)(&ts);

	eth->s_addr.addr_bytes[3]= pt[0];
	eth->s_addr.addr_bytes[2]= pt[1];
	eth->s_addr.addr_bytes[1]= pt[2];
	eth->s_addr.addr_bytes[0]= pt[3];

	eth->s_addr.addr_bytes[4]= (uint8_t)(0x99);
	eth->s_addr.addr_bytes[5]= (uint8_t)(0x99);

	ether_addr_copy(&pkt->eth_dst_addr, &eth->d_addr);

	flags = rte_atomic32_read(&info->port_flags);
	if (flags & SEND_VLAN_ID) {
		/* vlan ethernet header */
		eth->ether_type = htons(ETHER_TYPE_VLAN);

		/* only set the TCI field for now; don't bother with PCP/DEI */
		struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)(eth + 1);
		vlan_hdr->vlan_tci = htons(pkt->vlanid);
		vlan_hdr->eth_proto = htons(pkt->ethType);

		/* adjust header size for VLAN tag */
		pkt->ether_hdr_size = sizeof(struct ether_hdr) +
			sizeof(struct vlan_hdr);

		return (char *)(vlan_hdr + 1);
	} else if (rte_atomic32_read(&info->port_flags) & SEND_MPLS_LABEL) {
		/* MPLS unicast ethernet header */
		eth->ether_type = htons(ETHER_TYPE_MPLS_UNICAST);

		mplsHdr_t *mpls_hdr = (mplsHdr_t *)(eth + 1);

		/* Only a single MPLS label is supported at the moment. Make sure the
		 * BoS flag is set. */
		uint32_t mpls_label = pkt->mpls_entry;
		MPLS_SET_BOS(mpls_label);

		mpls_hdr->label = htonl(mpls_label);

		/* Adjust header size for MPLS label */
		pkt->ether_hdr_size = sizeof(struct ether_hdr) +
			sizeof(mplsHdr_t);

		return (char *)(mpls_hdr + 1);
	} else if (rte_atomic32_read(&info->port_flags) & SEND_Q_IN_Q_IDS) {
		/* Q-in-Q ethernet header */
		eth->ether_type = htons(ETHER_TYPE_Q_IN_Q);

		qinqHdr_t *qinq_hdr = (qinqHdr_t *)(eth + 1);

		/* only set the TCI field for now; don't bother with PCP/DEI */
		qinq_hdr->qinq_tci = htons(pkt->qinq_outerid);

		qinq_hdr->vlan_tpid = htons(ETHER_TYPE_VLAN);
		qinq_hdr->vlan_tci = htons(pkt->qinq_innerid);

		qinq_hdr->eth_proto = htons(pkt->ethType);

		/* Adjust header size for Q-in-Q header */
		pkt->ether_hdr_size = sizeof(struct ether_hdr) +
			sizeof(qinqHdr_t);

		return (char *)(qinq_hdr + 1);
	} else {
		/* normal ethernet header */
		eth->ether_type = htons(pkt->ethType);
		pkt->ether_hdr_size = sizeof(struct ether_hdr);
	}

	return (char *)(eth + 1);
}
