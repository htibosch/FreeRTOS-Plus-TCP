/*
 * FreeRTOS+TCP <DEVELOPMENT BRANCH>
 * Copyright (C) 2022 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/**
 * @file FreeRTOS_TCP_State_Handling_IPv6.c
 * @brief Module which handles the TCP protocol state transition for FreeRTOS+TCP.
 *
 * Endianness: in this module all ports and IP addresses are stored in
 * host byte-order, except fields in the IP-packets
 */

/* Standard includes. */
#include <stdint.h>
#include <stdio.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_DHCP.h"
#include "NetworkInterface.h"
#include "NetworkBufferManagement.h"

#include "FreeRTOS_TCP_Reception.h"
#include "FreeRTOS_TCP_Transmission.h"
#include "FreeRTOS_TCP_State_Handling.h"
#include "FreeRTOS_TCP_Utils.h"

/* Just make sure the contents doesn't get compiled if TCP is not enabled. */
/* *INDENT-OFF* */
#if( ipconfigUSE_IPv6 != 0 ) && ( ipconfigUSE_TCP == 1 )
/* *INDENT-ON* */

#if ipconfigIS_ENABLED( ipconfigHAS_TCP_ACCEPT_HOOK )

/*
 * This hook allows the user to allow specific IP-addreses and/or
 * port ranges.
 */

static BaseType_t xIP_Address_allowed_v6( NetworkBufferDescriptor_t * pxNetworkBuffer );

#endif

/**
 * @brief Handle 'listen' event on the given socket.
 *
 * @param[in] pxSocket The socket on which the listen occurred.
 * @param[in] pxNetworkBuffer The network buffer carrying the packet.
 *
 * @return If a new socket/duplicate socket is created, then the pointer to
 *         that socket is returned or else, a NULL pointer is returned.
 */
FreeRTOS_Socket_t * prvHandleListen_IPV6( FreeRTOS_Socket_t * pxSocket,
                                          NetworkBufferDescriptor_t * pxNetworkBuffer )
{
    const TCPPacket_IPv6_t * pxTCPPacket = NULL;
    FreeRTOS_Socket_t * pxReturn = NULL;
    uint32_t ulInitialSequenceNumber = 0;
    BaseType_t xHasSequence = pdFALSE;
    BaseType_t xIsNewSocket = pdFALSE;

    if( ( pxSocket != NULL ) && ( pxNetworkBuffer != NULL ) )
    {
        /* Map the ethernet buffer onto a TCPPacket_IPv6_t struct for easy access to the fields. */

        /* MISRA Ref 11.3.1 [Misaligned access] */
        /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
        /* coverity[misra_c_2012_rule_11_3_violation] */
        pxTCPPacket = ( ( const TCPPacket_IPv6_t * ) pxNetworkBuffer->pucEthernetBuffer );

        configASSERT( pxNetworkBuffer->pxEndPoint != NULL );

        /* Silently discard a SYN packet which was not specifically sent for this node. */
        if( memcmp( pxTCPPacket->xIPHeader.xDestinationAddress.ucBytes, pxNetworkBuffer->pxEndPoint->ipv6_settings.xIPAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS ) == 0 )
        {
            /* Assume that a new Initial Sequence Number will be required. Request
             * it now in order to fail out if necessary. */
            if( xApplicationGetRandomNumber( &ulInitialSequenceNumber ) == pdPASS )
            {
                xHasSequence = pdTRUE;
            }
        }
    }

    /* A pure SYN (without ACK) has come in, create a new socket to answer
     * it. */
    if( xHasSequence != pdFALSE )
    {
        if( pxSocket->u.xTCP.bits.bReuseSocket != pdFALSE_UNSIGNED )
        {
            /* The flag bReuseSocket indicates that the same instance of the
             * listening socket should be used for the connection. */
            pxReturn = pxSocket;
            pxSocket->u.xTCP.bits.bPassQueued = pdTRUE_UNSIGNED;
            pxSocket->u.xTCP.pxPeerSocket = pxSocket;
        }
        else
        {
            /* The socket does not have the bReuseSocket flag set meaning create a
             * new socket when a connection comes in. */
            pxReturn = NULL;

#if ipconfigIS_ENABLED( ipconfigHAS_TCP_ACCEPT_HOOK )
			if( xIP_Address_allowed_v6 ( pxNetworkBuffer ) == pdFALSE )
			{
                ( void ) prvTCPSendReset( pxNetworkBuffer );
            }
            else
#endif
			if( pxSocket->u.xTCP.usChildCount >= pxSocket->u.xTCP.usBacklog )
            {
                FreeRTOS_printf( ( "Check: Socket %u already has %u / %u child%s\n",
                                   pxSocket->usLocalPort,
                                   pxSocket->u.xTCP.usChildCount,
                                   pxSocket->u.xTCP.usBacklog,
                                   ( pxSocket->u.xTCP.usChildCount == 1U ) ? "" : "ren" ) );
                ( void ) prvTCPSendReset( pxNetworkBuffer );
            }
            else
            {
                FreeRTOS_Socket_t * pxNewSocket = ( FreeRTOS_Socket_t * )
                                                  FreeRTOS_socket( FREERTOS_AF_INET6, FREERTOS_SOCK_STREAM, FREERTOS_IPPROTO_TCP );

                /* MISRA Ref 11.4.1 [Socket error and integer to pointer conversion] */
                /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-114 */
                /* coverity[misra_c_2012_rule_11_4_violation] */
                if( ( pxNewSocket == NULL ) || ( pxNewSocket == FREERTOS_INVALID_SOCKET ) )
                {
                    FreeRTOS_debug_printf( ( "TCP: Listen: new socket failed\n" ) );
                    ( void ) prvTCPSendReset( pxNetworkBuffer );
                }
                else if( prvTCPSocketCopy( pxNewSocket, pxSocket ) != pdFALSE )
                {
                    /* The socket will be connected immediately, no time for the
                     * owner to setsockopt's, therefore copy properties of the server
                     * socket to the new socket.  Only the binding might fail (due to
                     * lack of resources). */
                    pxReturn = pxNewSocket;
                    xIsNewSocket = pdTRUE;
                }
                else
                {
                    /* Copying failed somehow. */
                }
            }
        }
    }

    if( ( xHasSequence != pdFALSE ) && ( pxReturn != NULL ) )
    {
        do
        {
            size_t xCopyLength;
            const IPHeader_IPv6_t * pxIPHeader_IPv6;
            BaseType_t xReturnCreateWindow;

            /* Map the byte stream onto the ProtocolHeaders_t for easy access to the fields. */

            /* MISRA Ref 11.3.1 [Misaligned access] */
            /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
            /* coverity[misra_c_2012_rule_11_3_violation] */
            const ProtocolHeaders_t * pxProtocolHeaders = ( ( const ProtocolHeaders_t * )
                                                            &( pxNetworkBuffer->pucEthernetBuffer[ ipSIZE_OF_ETH_HEADER + uxIPHeaderSizePacket( pxNetworkBuffer ) ] ) );

            pxReturn->pxEndPoint = pxNetworkBuffer->pxEndPoint;
            pxReturn->bits.bIsIPv6 = pdTRUE_UNSIGNED;

            /* MISRA Ref 11.3.1 [Misaligned access] */
            /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
            /* coverity[misra_c_2012_rule_11_3_violation] */
            pxIPHeader_IPv6 = ( ( const IPHeader_IPv6_t * ) &( pxNetworkBuffer->pucEthernetBuffer[ ipSIZE_OF_ETH_HEADER ] ) );
            pxReturn->u.xTCP.usRemotePort = FreeRTOS_ntohs( pxTCPPacket->xTCPHeader.usSourcePort );
            ( void ) memcpy( pxReturn->u.xTCP.xRemoteIP.xIP_IPv6.ucBytes, pxIPHeader_IPv6->xSourceAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
            pxReturn->u.xTCP.xTCPWindow.ulOurSequenceNumber = ulInitialSequenceNumber;

            /* Here is the SYN action. */
            pxReturn->u.xTCP.xTCPWindow.rx.ulCurrentSequenceNumber = FreeRTOS_ntohl( pxProtocolHeaders->xTCPHeader.ulSequenceNumber );
            prvSocketSetMSS( pxReturn );

            xReturnCreateWindow = prvTCPCreateWindow( pxReturn );

            /* Did allocating TCP sectors fail? */
            if( xReturnCreateWindow != pdPASS )
            {
                /* Close the socket if it was newly created. */
                if( xIsNewSocket == pdTRUE )
                {
                    ( void ) vSocketClose( pxReturn );
                }

                pxReturn = NULL;
                break;
            }

            vTCPStateChange( pxReturn, eSYN_FIRST );

            /* Make a copy of the header up to the TCP header.  It is needed later
             * on, whenever data must be sent to the peer. */
            if( pxNetworkBuffer->xDataLength > sizeof( pxReturn->u.xTCP.xPacket.u.ucLastPacket ) )
            {
                xCopyLength = sizeof( pxReturn->u.xTCP.xPacket.u.ucLastPacket );
            }
            else
            {
                xCopyLength = pxNetworkBuffer->xDataLength;
            }

            ( void ) memcpy( ( void * ) pxReturn->u.xTCP.xPacket.u.ucLastPacket,
                             ( const void * ) pxNetworkBuffer->pucEthernetBuffer,
                             xCopyLength );
        } while( ipFALSE_BOOL );
    }

    return pxReturn;
}
/*-----------------------------------------------------------*/

#if ipconfigIS_ENABLED( ipconfigHAS_TCP_ACCEPT_HOOK )

static BaseType_t xIP_Address_allowed_v6( NetworkBufferDescriptor_t * pxNetworkBuffer )
{
    /* MISRA Ref 11.3.1 [Misaligned access] */
    /* More details at: https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/main/MISRA.md#rule-113 */
    /* coverity[misra_c_2012_rule_11_3_violation] */
    const TCPPacket_t * pxTCPPacket = ( ( const TCPPacket_t * ) pxNetworkBuffer->pucEthernetBuffer );
    IPv46_Address_t xSourceAddress;
    IPv46_Address_t xTargetAddress;
	uint16_t usSourcePort;
	uint16_t usTargetPort;
	BaseType_t xReturn;

	const IPHeader_IPv6_t * pxIPHeader_IPv6 = ( ( const IPHeader_IPv6_t * ) &( pxNetworkBuffer->pucEthernetBuffer[ ipSIZE_OF_ETH_HEADER ] ) );

    usSourcePort = pxTCPPacket->xTCPHeader.usSourcePort;
	xSourceAddress.xIs_IPv6 = pdTRUE;
	memcpy( xSourceAddress.xIPAddress.xIP_IPv6.ucBytes, pxIPHeader_IPv6->xSourceAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
	
	usTargetPort = pxTCPPacket->xTCPHeader.usDestinationPort;
	xTargetAddress.xIs_IPv6 = pdTRUE;
	memcpy( xTargetAddress.xIPAddress.xIP_IPv6.ucBytes, pxIPHeader_IPv6->xDestinationAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
    /* '%pip' is a printf format to print an IPv6 address.
     * It expects an array of char's.
     * '%xip' prints an IPv4 address.
     * It expects a uint32_t
     */
	FreeRTOS_printf( ( "Local address  [%pip]:%u\n",
		xTargetAddress.xIPAddress.xIP_IPv6.ucBytes,
		FreeRTOS_htons( usTargetPort ) ) );
	FreeRTOS_printf( ( "Remote address [%pip]:%u\n",
		xSourceAddress.xIPAddress.xIP_IPv6.ucBytes,
		FreeRTOS_htons( usSourcePort ) ) );

	xReturn = xApplicationTCPAcceptHook(
		&xSourceAddress,
		usSourcePort,
		&xTargetAddress,
		usTargetPort );
	return xReturn;
}

#endif /* ipconfigIS_ENABLED( ipconfigHAS_TCP_ACCEPT_HOOK ) */

/* *INDENT-OFF* */
#endif /* ( ipconfigUSE_IPv6 != 0 ) && ( ipconfigUSE_TCP == 1 ) */
/* *INDENT-ON* */
