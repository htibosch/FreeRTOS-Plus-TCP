/*
 * FreeRTOS+TCP V2.3.1
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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
 * @file FreeRTOS_DNS.c
 * @brief Implements the Domain Name System for the FreeRTOS+TCP network stack.
 */

/* Standard includes. */
#include <stdint.h>
#include <stdio.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

/* FreeRTOS+TCP includes. */
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "FreeRTOS_IP_Private.h"
#include "FreeRTOS_UDP_IP.h"
#include "FreeRTOS_DNS.h"
#include "FreeRTOS_DHCP.h"
#include "NetworkBufferManagement.h"
#include "FreeRTOS_Routing.h"

/* Exclude the entire file if DNS is not enabled. */
#if ( ipconfigUSE_DNS != 0 )

    #if ( ipconfigBYTE_ORDER == pdFREERTOS_LITTLE_ENDIAN )
        #define dnsDNS_PORT             0x3500U  /**< Little endian: Port used for DNS. */
        #define dnsONE_QUESTION         0x0100U  /**< Little endian representation of a DNS question.*/
        #define dnsOUTGOING_FLAGS       0x0001U  /**< Little endian representation of standard query. */
        #define dnsRX_FLAGS_MASK        0x0f80U  /**< Little endian:  The bits of interest in the flags field of incoming DNS messages. */
        #define dnsEXPECTED_RX_FLAGS    0x0080U  /**< Little Endian: Should be a response, without any errors. */
    #else
        #define dnsDNS_PORT             0x0035U  /**< Big endian: Port used for DNS. */
        #define dnsONE_QUESTION         0x0001U  /**< Big endian representation of a DNS question.*/
        #define dnsOUTGOING_FLAGS       0x0100U  /**< Big endian representation of standard query. */
        #define dnsRX_FLAGS_MASK        0x800fU  /**< Big endian: The bits of interest in the flags field of incoming DNS messages. */
        #define dnsEXPECTED_RX_FLAGS    0x8000U  /**< Big endian: Should be a response, without any errors. */

    #endif /* ipconfigBYTE_ORDER */

/** @brief The maximum number of times a DNS request should be sent out if a response
 * is not received, before giving up. */
    #ifndef ipconfigDNS_REQUEST_ATTEMPTS
        #define ipconfigDNS_REQUEST_ATTEMPTS    5
    #endif

/** @brief If the top two bits in the first character of a name field are set then the
 * name field is an offset to the string, rather than the string itself. */
    #define dnsNAME_IS_OFFSET    ( ( uint8_t ) 0xc0 )

/* NBNS flags. */
    #if ( ipconfigUSE_NBNS == 1 )
        #define dnsNBNS_FLAGS_RESPONSE        0x8000U /**< NBNS response flag. */
        #define dnsNBNS_FLAGS_OPCODE_MASK     0x7800U /**< NBNS opcode bitmask. */
        #define dnsNBNS_FLAGS_OPCODE_QUERY    0x0000U /**< NBNS opcode query. */
    #endif /* ( ipconfigUSE_NBNS == 1 ) */

/* Host types. */
    #define dnsCLASS_IN                  0x01U /**< DNS class IN (Internet). */

/* LLMNR constants. */
    #define dnsLLMNR_TTL_VALUE           300000U  /**< LLMNR time to live value. */
    #define dnsLLMNR_FLAGS_IS_REPONSE    0x8000U  /**< LLMNR flag value for response. */

/* NBNS constants. */
    #if ( ipconfigUSE_NBNS != 0 )
        #define dnsNBNS_TTL_VALUE               3600U   /**< NBNS TTL: 1 hour valid. */
        #define dnsNBNS_TYPE_NET_BIOS           0x0020U /**< NBNS Type: NetBIOS. */
        #define dnsNBNS_CLASS_IN                0x01U   /**< NBNS Class: IN (Internet). */
        #define dnsNBNS_NAME_FLAGS              0x6000U /**< NBNS name flags. */
        #define dnsNBNS_ENCODED_NAME_LENGTH     32      /**< NBNS encoded name length. */

/** @brief If the queried NBNS name matches with the device's name,
 * the query will be responded to with these flags: */
        #define dnsNBNS_QUERY_RESPONSE_FLAGS    ( 0x8500U )
    #endif /* ( ipconfigUSE_NBNS != 0 ) */

/** @brief Flag DNS parsing errors in situations where an IPv4 address is the return
 * type. */
    #define dnsPARSE_ERROR    0U

    #if ( ipconfigUSE_DNS_CACHE == 0 )
        #if ( ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY != 1 )
            #error When DNS caching is disabled, please make ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY equal to 1.
        #endif
    #endif

/** @brief Define the ASCII value of '.' (Period/Full-stop). */
    #define ASCII_BASELINE_DOT    46U

/*
 * Create a socket.  Return the created socket - or NULL if the socket could
 * not be created.
 */
    static Socket_t prvCreateDNSSocket( void );

/*
 * Bind the socket to a port number.
 */
    static BaseType_t prvBindDNSSocket( Socket_t xSocket,
                                        uint16_t usPort );

/*
 * Create the DNS message in the zero copy buffer passed in the first parameter.
 * uxIdentifier is a random identifier for this look-up, uxHostType is the type
 * of host wanted, dnsTYPE_A_HOST or dnsTYPE_AAA_HOST, i.e. IPv4 or IPv6 resp.
 */
    static size_t prvCreateDNSMessage( uint8_t * pucUDPPayloadBuffer,
                                       const char * pcHostName,
                                       TickType_t uxIdentifier,
                                       UBaseType_t uxHostType );

/*
 * Process a response packet from a DNS server.
 * The parameter 'xExpected' indicates whether the identifier in the reply
 * was expected, and thus if the DNS cache may be updated with the reply.
 * The IP address found will be stored in 'ppxAddressInfo' ( IPv4 or IPv6 ).
 * ppxAddressInfo may be NULL if the caller is not interested in the answers.
 */
    static uint32_t prvParseDNSReply( uint8_t * pucUDPPayloadBuffer,
                                      size_t uxBufferLength,
                                      struct freertos_addrinfo ** ppxAddressInfo,
                                      BaseType_t xExpected,
                                      uint16_t usPort );

/*
 * Check if hostname is a literal IP-address, check if the host is found in
 * the DNS cache, and when still not resolved, call prvGetHostByName() to
 * send a DNS request.
 */
    #if ( ipconfigDNS_USE_CALLBACKS == 1 )
        static uint32_t prvPrepareLookup( const char * pcHostName,
                                          struct freertos_addrinfo ** ppxAddressInfo,
                                          BaseType_t xFamily, /* FREERTOS_AF_INET4 / 6. */
                                          FOnDNSEvent pCallbackFunction,
                                          void * pvSearchID,
                                          TickType_t uxTimeout );
    #else
        static uint32_t prvPrepareLookup( const char * pcHostName,
                                          struct freertos_addrinfo ** ppxAddressInfo,
                                          BaseType_t xFamily ); /* FREERTOS_AF_INET4 / 6. */
    #endif /* ( ipconfigDNS_USE_CALLBACKS == 1 ) */

/*
 * Prepare and send a message to a DNS server.  'uxReadTimeOut_ticks' will be passed as
 * zero, in case the user has supplied a call-back function.
 */
    static uint32_t prvGetHostByName( const char * pcHostName,
                                      TickType_t uxIdentifier,
                                      TickType_t uxReadTimeOut_ticks,
                                      struct freertos_addrinfo ** ppxAddressInfo,
                                      BaseType_t xFamily );

    #if ( ipconfigDNS_USE_CALLBACKS == 1 )
        #if ( ipconfigUSE_IPv6 != 0 )
            static void vDNSSetCallBack( const char * pcHostName,
                                         void * pvSearchID,
                                         FOnDNSEvent pCallbackFunction,
                                         TickType_t uxTimeout,
                                         TickType_t uxIdentifier,
                                         BaseType_t xIsIPv6 );
        #else
            static void vDNSSetCallBack( const char * pcHostName,
                                         void * pvSearchID,
                                         FOnDNSEvent pCallbackFunction,
                                         TickType_t uxTimeout,
                                         TickType_t uxIdentifier );
        #endif /* ipconfigUSE_IPv6 */
    #endif /* ipconfigDNS_USE_CALLBACKS */

    #if ( ipconfigDNS_USE_CALLBACKS != 0 )
        #if ( ipconfigUSE_IPv6 != 0 )
            static BaseType_t xDNSDoCallback( ParseSet_t * pxSet,
                                              struct freertos_addrinfo * pxAddress );
        #else
            static BaseType_t xDNSDoCallback( ParseSet_t * pxSet,
                                              uint32_t ulIPAddress );
        #endif /* ( ipconfigUSE_IPv6 != 0 ) */
    #endif /* ipconfigDNS_USE_CALLBACKS */

/*
 * The NBNS and the LLMNR protocol share this reply function.
 */
    #if ( ( ipconfigUSE_NBNS == 1 ) || ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )
        static void prvReplyDNSMessage( NetworkBufferDescriptor_t * pxNetworkBuffer,
                                        BaseType_t lNetLength );
    #endif

    #if ( ipconfigUSE_NBNS == 1 )
        static portINLINE void prvTreatNBNS( uint8_t * pucPayload,
                                             size_t uxBufferLength,
                                             uint32_t ulIPAddress );
    #endif /* ipconfigUSE_NBNS */


    #if ( ipconfigUSE_DNS_CACHE == 1 ) || ( ipconfigDNS_USE_CALLBACKS == 1 )
        _static size_t prvReadNameField( ParseSet_t * pxSet,
                                         size_t uxDestLen );
    #endif /* ipconfigUSE_DNS_CACHE || ipconfigDNS_USE_CALLBACKS */

    #if ( ipconfigUSE_DNS_CACHE == 1 )
        /** @brief Copy DNS cache entries at xIndex to a linked struct addrinfo. */
        static void prvReadDNSCache( BaseType_t xIndex,
                                     struct freertos_addrinfo ** ppxAddressInfo );
    #endif

/** @brief This function is called by the macro 'vSetField16'. It store
 *         a 16-bit number in a buffer in big-endian format ( MSB first ).
 * @param[in] pucBase: A pointer to a buffer where to store a uint16_t.
 * @param[in] uxOffset: The offset within pucBase.
 * @param[in] usValue: The 16-bit value to be stored.
 */
    void vSetField16helper( uint8_t * pucBase,
                            size_t uxOffset,
                            uint16_t usValue )
    {
        pucBase[ uxOffset ] = ( uint8_t ) ( ( ( usValue ) >> 8 ) & 0xffU );
        pucBase[ uxOffset + 1U ] = ( uint8_t ) ( ( usValue ) & 0xffU );
    }

/** @brief This function is called by the macro 'vSetField32'. It store
 *         a 43-bit number in a buffer in big-endian format.
 * @param[in] pucBase: A pointer to a buffer where to store a uint32_t.
 * @param[in] uxOffset: The offset within pucBase.
 * @param[in] ulValue: The word to be stored.
 */
    void vSetField32helper( uint8_t * pucBase,
                            size_t uxOffset,
                            uint32_t ulValue )
    {
        pucBase[ uxOffset + 0U ] = ( uint8_t ) ( ( ulValue ) >> 24 );
        pucBase[ uxOffset + 1U ] = ( uint8_t ) ( ( ( ulValue ) >> 16 ) & 0xffU );
        pucBase[ uxOffset + 2U ] = ( uint8_t ) ( ( ( ulValue ) >> 8 ) & 0xffU );
        pucBase[ uxOffset + 3U ] = ( uint8_t ) ( ( ulValue ) & 0xffU );
    }

/** @brief A struct that can hold either an IPv4 or an IPv6 address. */
    typedef struct xxIPv46_Address
    {
        /* A struct that can hold either an IPv4 or an IPv6 address. */
        uint32_t ulIPAddress;             /**< The IPv4-address. */
        #if ( ipconfigUSE_IPv6 != 0 )
            IPv6_Address_t xAddress_IPv6; /**< The IPv6-address. */
            BaseType_t xIs_IPv6;          /**< pdTRUE if the IPv6 member is used. */
        #endif /* ( ipconfigUSE_IPv6 != 0 ) */
    } IPv46_Address_t;

    #if ( ipconfigUSE_DNS_CACHE == 1 )
        static BaseType_t prvProcessDNSCache( const char * pcName,
                                              IPv46_Address_t * pxIP,
                                              uint32_t ulTTL,
                                              BaseType_t xLookUp,
                                              struct freertos_addrinfo ** ppxAddressInfo );

        typedef struct xDNS_CACHE_TABLE_ROW
        {
            IPv46_Address_t xAddresses[ ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY ]; /* The IP address(es) of an ARP cache entry. */
            char pcName[ ipconfigDNS_CACHE_NAME_LENGTH ];                        /* The name of the host */
            uint32_t ulTTL;                                                      /* Time-to-Live (in seconds) from the DNS server. */
            uint32_t ulTimeWhenAddedInSeconds;
            #if ( ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY > 1 )
                uint8_t ucNumIPAddresses;
                uint8_t ucCurrentIPAddress;
            #endif
        } DNSCacheRow_t;

        static DNSCacheRow_t xDNSCache[ ipconfigDNS_CACHE_ENTRIES ];
        static BaseType_t xFreeDNSEntry = 0;

/* Utility function: Clear DNS cache by calling this function. */
        void FreeRTOS_dnsclear( void )
        {
            ( void ) memset( xDNSCache, 0x0, sizeof( xDNSCache ) );
            xFreeDNSEntry = 0;
        }
    #endif /* ipconfigUSE_DNS_CACHE == 1 */

    #if ( ipconfigUSE_LLMNR == 1 )
        /** @brief The MAC address used for LLMNR. */
        const MACAddress_t xLLMNR_MacAdress = { { 0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc } };
    #endif /* ipconfigUSE_LLMNR == 1 */

    #if ( ipconfigUSE_LLMNR == 1 ) && ( ipconfigUSE_IPv6 != 0 )
        const IPv6_Address_t ipLLMNR_IP_ADDR_IPv6 =
        {
            #ifndef _MSC_VER
                /* MSC doesn't like this C-style initialisation. */
                ucBytes :
            #endif
            { /* ff02::1:3 */
                0xff, 0x02,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x01,
                0x00, 0x03,
            }
        };
        const MACAddress_t xLLMNR_MacAdressIPv6 = { { 0x33, 0x33, 0x00, 0x01, 0x00, 0x03 } };
    #endif /* ipconfigUSE_LLMNR && ipconfigUSE_IPv6 */

    #if ( ipconfigUSE_MDNS == 1 ) && ( ipconfigUSE_IPv6 != 0 )
        const IPv6_Address_t ipMDNS_IP_ADDR_IPv6 =
        {
            #ifndef _MSC_VER
                /* MSC doesn't like this C-style initialisation. */
                ucBytes :
            #endif
            { /* ff02::fb */
                0xff, 0x02,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0xfb,
            }
        };

/* The MAC-addresses are provided here in case a network
 * interface needs it. */
        const MACAddress_t xMDNS_MACAdressIPv6 = { { 0x33, 0x33, 0x00, 0x00, 0x00, 0xFB } };
    #endif /* ( ipconfigUSE_MDNS == 1 ) && ( ipconfigUSE_IPv6 != 0 ) */


    #if ( ipconfigUSE_MDNS == 1 )
        /** @brief The MAC address used for MDNS. */
        const MACAddress_t xMDNS_MacAdress = { { 0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb } };
    #endif /* ipconfigUSE_MDNS == 1 */

/* This global variable is being used to indicate to the driver which IP type
 * is preferred for name service lookup, either IPv6 or IPv4. */
    IPPreference_t xDNS_IP_Preference =
    #if ( ipconfigUSE_IPv6 != 0 )
            xPreferenceIPv6;
    #else
            xPreferenceIPv4;
    #endif
/*-----------------------------------------------------------*/

/**
 * @brief Utility function to cast pointer of a type to pointer of type DNSMessage_t.
 *
 * @return The casted pointer.
 */
        static ipDECL_CAST_PTR_FUNC_FOR_TYPE( DNSMessage_t );
    static ipDECL_CAST_PTR_FUNC_FOR_TYPE( DNSMessage_t )
    {
        return ( DNSMessage_t * ) pvArgument;
    }

/**
 * @brief Utility function to cast a const pointer of a type to a const pointer of type DNSMessage_t.
 *
 * @return The casted pointer.
 */
    static ipDECL_CAST_CONST_PTR_FUNC_FOR_TYPE( DNSMessage_t );
    static ipDECL_CAST_CONST_PTR_FUNC_FOR_TYPE( DNSMessage_t )
    {
        return ( const DNSMessage_t * ) pvArgument;
    }

/* A DNS query consists of a header, as described in 'struct xDNSMessage'
 * It is followed by 1 or more queries, each one consisting of a name and a tail,
 * with two fields: type and class
 */
    #include "pack_struct_start.h"
    struct xDNSTail
    {
        uint16_t usType;  /**< Type of DNS message. */
        uint16_t usClass; /**< Class of DNS message. */
    }
    #include "pack_struct_end.h"
    typedef struct xDNSTail DNSTail_t;

/* DNS answer record header. */
    #include "pack_struct_start.h"
    struct xDNSAnswerRecord
    {
        uint16_t usType;       /**< Type of DNS answer record. */
        uint16_t usClass;      /**< Class of DNS answer record. */
        uint32_t ulTTL;        /**< Number of seconds the result can be cached. */
        uint16_t usDataLength; /**< Length of the data field. */
    }
    #include "pack_struct_end.h"
    typedef struct xDNSAnswerRecord DNSAnswerRecord_t;
/** @brief Used for additional error checking when asserts are enabled. */
    _static struct freertos_addrinfo * pxLastInfo = NULL;

    static BaseType_t prvParseDNS_ReadQuestions( ParseSet_t * pxSet );

/** @brief Parse the array of answers that are received from a DNS server. */
    static BaseType_t prvParseDNS_ReadAnswers( ParseSet_t * pxSet,
                                               struct freertos_addrinfo ** ppxAddressInfo );
    #if ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )

/** @brief An LLMNR or an mDNS lookup of a host was received. The application code
 *         is consulted by calling xApplicationDNSQueryHook(), which returns true
 *         in case the driver should reply to the lookup. */
        static void prvParseDNS_HandleLLMNRRequest( ParseSet_t * pxSet,
                                                    uint8_t * pucUDPPayloadBuffer );
    #endif

    #if ( ipconfigUSE_DNS_CACHE == 1 )
        static uint32_t prvPrepare_CacheLookup( const char * pcHostName,
                                                BaseType_t xFamily,
                                                struct freertos_addrinfo ** ppxAddressInfo );
    #endif

/** @brief See if pcHostName contains a valid IPv4 or IPv6 IP-address. */
    static uint32_t prvPrepare_ReadIPAddress( const char * pcHostName,
                                              BaseType_t xFamily,
                                              struct freertos_addrinfo ** ppxAddressInfo );

/** @brief Get an IP address ( IPv4 or IPv6 ) of a DNS server. */
    static NetworkEndPoint_t * prvGetDNSAddress( struct freertos_sockaddr * pxAddress,
                                                 const char * pcHostName );

    #if ( ipconfigUSE_DNS_CACHE == 1 )
        static void prvParseDNS_StoreToCache( ParseSet_t * pxSet,
                                              IPv46_Address_t * pxIP_Address,
                                              uint32_t ulTTL );
    #endif

    static void prvParseDNS_StoreAnswer( ParseSet_t * pxSet,
                                         IPv46_Address_t * pxIP_Address,
                                         struct freertos_addrinfo ** ppxAddressInfo );

    static struct freertos_addrinfo * pxNew_AddrInfo( const char * pcName,
                                                      BaseType_t xFamily,
                                                      const uint8_t * pucAddress );

    static void prvIncreaseDNS4Index( NetworkEndPoint_t * pxEndPoint );

    #if ( ipconfigUSE_IPv6 != 0 )
        static void prvIncreaseDNS6Index( NetworkEndPoint_t * pxEndPoint );
    #endif

    #if ( ( ipconfigUSE_NBNS == 1 ) || ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )
        static NetworkEndPoint_t * prvFindEndPointOnNetMask( NetworkBufferDescriptor_t * pxNetworkBuffer );
    #endif

/**
 * @brief Utility function to cast pointer of a type to pointer of type DNSAnswerRecord_t.
 *
 * @return The casted pointer.
 */
    static ipDECL_CAST_PTR_FUNC_FOR_TYPE( DNSAnswerRecord_t );
    static ipDECL_CAST_PTR_FUNC_FOR_TYPE( DNSAnswerRecord_t )
    {
        return ( DNSAnswerRecord_t * ) pvArgument;
    }

    #if ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )

        #include "pack_struct_start.h"
        struct xLLMNRAnswer
        {
            uint8_t ucNameCode;    /**< Name type. */
            uint8_t ucNameOffset;  /**< The name is not repeated in the answer, only the offset is given with "0xc0 <offs>" */
            uint16_t usType;       /**< Type of the Resource record. */
            uint16_t usClass;      /**< Class of the Resource record. */
            uint32_t ulTTL;        /**< Seconds till this entry can be cached. */
            uint16_t usDataLength; /**< Length of the address in this record. */
            uint32_t ulIPAddress;  /**< The IP-address. */
        }
        #include "pack_struct_end.h"
        typedef struct xLLMNRAnswer LLMNRAnswer_t;

/**
 * @brief Utility function to cast pointer of a type to pointer of type LLMNRAnswer_t.
 *
 * @return The casted pointer.
 */
        static ipDECL_CAST_PTR_FUNC_FOR_TYPE( LLMNRAnswer_t );
        static ipDECL_CAST_PTR_FUNC_FOR_TYPE( LLMNRAnswer_t )
        {
            return ( LLMNRAnswer_t * ) pvArgument;
        }


    #endif /* ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) ) */

    #if ( ipconfigUSE_NBNS == 1 )

        #include "pack_struct_start.h"
        struct xNBNSRequest
        {
            uint16_t usRequestId;                          /**< NBNS request ID. */
            uint16_t usFlags;                              /**< Flags of the DNS message. */
            uint16_t ulRequestCount;                       /**< The number of requests/questions in this query. */
            uint16_t usAnswerRSS;                          /**< The number of answers in this query. */
            uint16_t usAuthRSS;                            /**< Number of authoritative resource records. */
            uint16_t usAdditionalRSS;                      /**< Number of additional resource records. */
            uint8_t ucNameSpace;                           /**< Length of name. */
            uint8_t ucName[ dnsNBNS_ENCODED_NAME_LENGTH ]; /**< The domain name. */
            uint8_t ucNameZero;                            /**< Terminator of the name. */
            uint16_t usType;                               /**< Type of NBNS record. */
            uint16_t usClass;                              /**< Class of NBNS request. */
        }
        #include "pack_struct_end.h"
        typedef struct xNBNSRequest NBNSRequest_t;

        #include "pack_struct_start.h"
        struct xNBNSAnswer
        {
            uint16_t usType;       /**< Type of NBNS answer. */
            uint16_t usClass;      /**< Class of NBNS answer. */
            uint32_t ulTTL;        /**< Time in seconds for which the answer can be cached. */
            uint16_t usDataLength; /**< Data length. */
            uint16_t usNbFlags;    /**< NetBIOS flags 0x6000 : IP-address, big-endian. */
            uint32_t ulIPAddress;  /**< The IPv4 address. */
        }
        #include "pack_struct_end.h"
        typedef struct xNBNSAnswer NBNSAnswer_t;

/**
 * @brief Utility function to cast pointer of a type to pointer of type NBNSAnswer_t.
 *
 * @return The casted pointer.
 */
        static ipDECL_CAST_PTR_FUNC_FOR_TYPE( NBNSAnswer_t );
        static ipDECL_CAST_PTR_FUNC_FOR_TYPE( NBNSAnswer_t )
        {
            return ( NBNSAnswer_t * ) pvArgument;
        }

    #endif /* ipconfigUSE_NBNS == 1 */

/*-----------------------------------------------------------*/

    #if ( ipconfigUSE_DNS_CACHE == 1 )
        uint32_t FreeRTOS_dnslookup( const char * pcHostName )
        {
            IPv46_Address_t xIPv46_Address;

            /* Looking up an IPv4 address in the DNS cache. */
            ( void ) memset( &xIPv46_Address, 0, sizeof( xIPv46_Address ) );
            /* Also the fields 'xIs_IPv6' and 'ulIPAddress' have been cleared. */
            ( void ) prvProcessDNSCache( pcHostName, &( xIPv46_Address ), 0, pdTRUE, NULL );

            return xIPv46_Address.ulIPAddress;
        }
    #endif /* ipconfigUSE_DNS_CACHE == 1 */
/*-----------------------------------------------------------*/

    #if ( ipconfigUSE_DNS_CACHE == 1 ) && ( ipconfigUSE_IPv6 != 0 )
        uint32_t FreeRTOS_dnslookup6( const char * pcHostName,
                                      IPv6_Address_t * pxAddress_IPv6 )
        {
            IPv46_Address_t xIPv46_Address;
            BaseType_t xResult;
            uint32_t ulReturn = 0U;

            /* Looking up an IPv6 address in the DNS cache. */
            ( void ) memset( &xIPv46_Address, 0, sizeof xIPv46_Address );
            /* Let prvProcessDNSCache only return IPv6 addresses. */
            xIPv46_Address.xIs_IPv6 = pdTRUE;
            xResult = prvProcessDNSCache( pcHostName, &xIPv46_Address, 0, pdTRUE, NULL );

            if( xResult != pdFALSE )
            {
                ( void ) memcpy( pxAddress_IPv6->ucBytes, xIPv46_Address.xAddress_IPv6.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
                ulReturn = 1U;
            }

            return ulReturn;
        }
    #endif /* ( ipconfigUSE_DNS_CACHE == 1 ) && ( ipconfigUSE_IPv6 != 0 ) */
/*-----------------------------------------------------------*/

    #if ( ipconfigDNS_USE_CALLBACKS == 1 )

/** @brief The structure to hold information for a DNS callback. */
        typedef struct xDNS_Callback
        {
            TickType_t uxRemaningTime;     /**< Timeout in ms */
            FOnDNSEvent pCallbackFunction; /**< Function to be called when the address has been found or when a timeout has been reached */
            TimeOut_t uxTimeoutState;      /**< Timeout state. */
            void * pvSearchID;             /**< Search ID of the callback function. */
            struct xLIST_ITEM xListItem;   /**< List struct. */
            #if ( ipconfigUSE_IPv6 != 0 )
                /* Remember whether this was a IPv6 lookup. */
                BaseType_t xIsIPv6;
            #endif
            char pcName[ 1 ]; /**< 1 character name. */
        } DNSCallback_t;


/**
 * @brief Utility function to cast pointer of a type to pointer of type DNSCallback_t.
 *
 * @return The casted pointer.
 */
        static ipDECL_CAST_PTR_FUNC_FOR_TYPE( DNSCallback_t );
        static ipDECL_CAST_PTR_FUNC_FOR_TYPE( DNSCallback_t )
        {
            return ( DNSCallback_t * ) pvArgument;
        }

/** @brief The list of all callback structures. */
        static List_t xCallbackList;

/**
 * @brief Define FreeRTOS_gethostbyname() as a normal blocking call.
 *
 * @param[in] pcHostName: The hostname whose IP address is being searched for.
 *
 * @return The IP-address of the hostname.
 */
        uint32_t FreeRTOS_gethostbyname( const char * pcHostName )
        {
            return FreeRTOS_gethostbyname_a( pcHostName, NULL, ( void * ) NULL, 0U );
        }
        /*-----------------------------------------------------------*/

/** @brief Initialise the list of call-back structures.
 */
        void vDNSInitialise( void )
        {
            vListInitialise( &xCallbackList );
        }
        /*-----------------------------------------------------------*/

/**
 * @brief Iterate through the list of call-back structures and remove
 * old entries which have reached a timeout.
 * As soon as the list has become empty, the DNS timer will be stopped.
 * In case pvSearchID is supplied, the user wants to cancel a DNS request.
 *
 * @param[in] pvSearchID: The search ID of callback function whose associated
 *                 DNS request is being cancelled. If non-ID specific checking of
 *                 all requests is required, then this field should be kept as NULL.
 */
        void vDNSCheckCallBack( void * pvSearchID )
        {
            const ListItem_t * pxIterator;
            const ListItem_t * xEnd = ipCAST_CONST_PTR_TO_CONST_TYPE_PTR( ListItem_t, &( xCallbackList.xListEnd ) );

            /* When a DNS-search times out, the call-back function shall
             * be called. Store theses item in a temporary list.
             * Only when the scheduler is running, user functions
             * shall be called. */
            List_t xTempList;

            vListInitialise( &xTempList );

            vTaskSuspendAll();
            {
                for( pxIterator = ( const ListItem_t * ) listGET_NEXT( xEnd );
                     pxIterator != xEnd;
                     )
                {
                    DNSCallback_t * pxCallback = ipCAST_PTR_TO_TYPE_PTR( DNSCallback_t, listGET_LIST_ITEM_OWNER( pxIterator ) );
                    /* Move to the next item because we might remove this item */
                    pxIterator = ( const ListItem_t * ) listGET_NEXT( pxIterator );

                    if( ( pvSearchID != NULL ) && ( pvSearchID == pxCallback->pvSearchID ) )
                    {
                        ( void ) uxListRemove( &( pxCallback->xListItem ) );
                        vPortFree( pxCallback );
                    }
                    else if( xTaskCheckForTimeOut( &pxCallback->uxTimeoutState, &( pxCallback->uxRemaningTime ) ) != pdFALSE )
                    {
                        /* A time-out occurred in the asynchronous search.
                         * Remove it from xCallbackList. */
                        ( void ) uxListRemove( &( pxCallback->xListItem ) );

                        /* Insert it in a temporary list. The function will be called
                         * once the scheduler is resumed. */
                        vListInsertEnd( &( xTempList ), &pxCallback->xListItem );
                    }
                    else
                    {
                        /* This call-back is still waiting for a reply or a time-out. */
                    }
                }
            }
            ( void ) xTaskResumeAll();

            if( listLIST_IS_EMPTY( &xTempList ) != pdFALSE )
            {
                /* There is at least one item in xTempList which must be removed and deleted. */
                xEnd = ipCAST_CONST_PTR_TO_CONST_TYPE_PTR( ListItem_t, &( xTempList.xListEnd ) );

                for( pxIterator = ( const ListItem_t * ) listGET_NEXT( xEnd );
                     pxIterator != xEnd;
                     )
                {
                    DNSCallback_t * pxCallback = ipCAST_PTR_TO_TYPE_PTR( DNSCallback_t, listGET_LIST_ITEM_OWNER( pxIterator ) );
                    /* Move to the next item because we might remove this item */
                    pxIterator = ( const ListItem_t * ) listGET_NEXT( pxIterator );

                    /* A time-out occurred in the asynchronous search.
                     * Call the application hook with the proper information. */
                    #if ( ipconfigUSE_IPv6 != 0 )
                        {
                            pxCallback->pCallbackFunction( pxCallback->pcName, pxCallback->pvSearchID, NULL );
                        }
                    #else
                        {
                            pxCallback->pCallbackFunction( pxCallback->pcName, pxCallback->pvSearchID, 0U );
                        }
                    #endif /* ( ipconfigUSE_IPv6 != 0 ) */
                    /* Remove it from 'xTempList' and free the memory. */
                    ( void ) uxListRemove( &( pxCallback->xListItem ) );
                    vPortFree( pxCallback );
                }
            }

            if( listLIST_IS_EMPTY( &xCallbackList ) != pdFALSE )
            {
                vIPSetDnsTimerEnableState( pdFALSE );
            }
        }
        /*-----------------------------------------------------------*/

/**
 * @brief Remove the entry defined by the search ID to cancel a DNS request.
 *
 * @param[in] pvSearchID: The search ID of the callback function associated with
 *                        the DNS request being cancelled. Note that the value of
 *                        the pointer matters, not the pointee.
 */
        void FreeRTOS_gethostbyname_cancel( void * pvSearchID )
        {
            vDNSCheckCallBack( pvSearchID );
        }
        /*-----------------------------------------------------------*/

        #if ( ipconfigUSE_IPv6 != 0 )

/**
 * @brief FreeRTOS_gethostbyname_a() was called along with callback parameters.
 *        Store them in a list for later reference.
 *
 * @param[in] pcHostName: The hostname whose IP address is being searched for.
 * @param[in] pvSearchID: The search ID of the DNS callback function to set.
 * @param[in] pCallbackFunction: The callback function pointer.
 * @param[in] uxTimeout: Timeout of the callback function.
 * @param[in] uxIdentifier: Random number used as ID in the DNS message.
 * @param[in] xIsIPv6: pdTRUE if the address type should be IPv6.
 */
            static void vDNSSetCallBack( const char * pcHostName,
                                         void * pvSearchID,
                                         FOnDNSEvent pCallbackFunction,
                                         TickType_t uxTimeout,
                                         TickType_t uxIdentifier,
                                         BaseType_t xIsIPv6 )
        #else

/**
 * @brief FreeRTOS_gethostbyname_a() was called along with callback parameters.
 *        Store them in a list for later reference.
 *
 * @param[in] pcHostName: The hostname whose IP address is being searched for.
 * @param[in] pvSearchID: The search ID of the DNS callback function to set.
 * @param[in] pCallbackFunction: The callback function pointer.
 * @param[in] uxTimeout: Timeout of the callback function.
 * @param[in] uxIdentifier: Random number used as ID in the DNS message.
 */
            static void vDNSSetCallBack( const char * pcHostName,
                                         void * pvSearchID,
                                         FOnDNSEvent pCallbackFunction,
                                         TickType_t uxTimeout,
                                         TickType_t uxIdentifier )
        #endif /* ( ipconfigUSE_IPv6 != 0 ) */
        {
            size_t uxLength = strlen( pcHostName );
            DNSCallback_t * pxCallback = ipCAST_PTR_TO_TYPE_PTR( DNSCallback_t, pvPortMalloc( sizeof( *pxCallback ) + uxLength ) );

            /* Translate from ms to number of clock ticks. */
            uxTimeout /= portTICK_PERIOD_MS;

            if( pxCallback != NULL )
            {
                if( listLIST_IS_EMPTY( &xCallbackList ) != pdFALSE )
                {
                    /* This is the first one, start the DNS timer to check for timeouts */
                    vIPReloadDNSTimer( FreeRTOS_min_uint32( 1000U, uxTimeout ) );
                }

                ( void ) strcpy( pxCallback->pcName, pcHostName );
                pxCallback->pCallbackFunction = pCallbackFunction;
                pxCallback->pvSearchID = pvSearchID;
                pxCallback->uxRemaningTime = uxTimeout;
                #if ( ipconfigUSE_IPv6 != 0 )
                    {
                        pxCallback->xIsIPv6 = xIsIPv6;
                    }
                #endif /* ( ipconfigUSE_IPv6 != 0 ) */
                vTaskSetTimeOutState( &( pxCallback->uxTimeoutState ) );
                listSET_LIST_ITEM_OWNER( &( pxCallback->xListItem ), ( void * ) pxCallback );
                listSET_LIST_ITEM_VALUE( &( pxCallback->xListItem ), uxIdentifier );
                vTaskSuspendAll();
                {
                    vListInsertEnd( &xCallbackList, &pxCallback->xListItem );
                }
                ( void ) xTaskResumeAll();
            }
        }
        /*-----------------------------------------------------------*/

        #if ( ipconfigUSE_IPv6 != 0 )

/**
 * @brief A DNS reply was received, see if there is any matching entry and
 *        call the handler.
 * @param[in,out] pxSet: a set of variables that are shared among the helper functions.
 * @param[in] pxAddress: IP-address ( IPv6/IPv4 ) obtained from the DNS server.
 *
 * @return Returns pdTRUE if uxIdentifier was recognized.
 */
            static BaseType_t xDNSDoCallback( ParseSet_t * pxSet,
                                              struct freertos_addrinfo * pxAddress )
        #else

/**
 * @brief A DNS reply was received, see if there is any matching entry and
 *        call the handler.
 * @param[in,out] pxSet: a set of variables that are shared among the helper functions.
 * @param[in] ulIPAddress: IP-address ( IPv4 ) obtained from the DNS server.
 *
 * @return Returns pdTRUE if uxIdentifier was recognized.
 */
            static BaseType_t xDNSDoCallback( ParseSet_t * pxSet,
                                              uint32_t ulIPAddress )
        #endif /* ( ipconfigUSE_IPv6 != 0 ) */
        {
            BaseType_t xResult = pdFALSE;
            const ListItem_t * pxIterator;
            const ListItem_t * xEnd = ipCAST_CONST_PTR_TO_CONST_TYPE_PTR( ListItem_t, &( xCallbackList.xListEnd ) );
            TickType_t uxIdentifier = ( TickType_t ) pxSet->pxDNSMessageHeader->usIdentifier;

            /* While iterating through the list, the scheduler is suspended.
             * Remember which function shall be called once the scheduler is
             * running again. */
            FOnDNSEvent pCallbackFunction = NULL;
            void * pvSearchID = NULL;

            vTaskSuspendAll();
            {
                for( pxIterator = ( const ListItem_t * ) listGET_NEXT( xEnd );
                     pxIterator != ( const ListItem_t * ) xEnd;
                     pxIterator = ( const ListItem_t * ) listGET_NEXT( pxIterator ) )
                {
                    BaseType_t xMatching;
                    DNSCallback_t * pxCallback = ipCAST_PTR_TO_TYPE_PTR( DNSCallback_t, listGET_LIST_ITEM_OWNER( pxIterator ) );
                    #if ( ipconfigUSE_MDNS == 1 )
                        /* mDNS port 5353. */
                        if( pxSet->usPortNumber == FreeRTOS_htons( ipMDNS_PORT ) )
                        {
                            /* In mDNS, the query ID field is ignored and the
                             * hostname will be compared with outstanding requests. */

                            xMatching = ( strcasecmp( pxCallback->pcName, pxSet->pcName ) == 0 ) ? pdTRUE : pdFALSE;
                        }
                        else
                    #endif /* if ( ipconfigUSE_MDNS == 1 ) */
                    {
                        xMatching = ( listGET_LIST_ITEM_VALUE( pxIterator ) == uxIdentifier ) ? pdTRUE : pdFALSE;
                    }

                    if( xMatching == pdTRUE )
                    {
                        pvSearchID = pxCallback->pvSearchID;
                        pCallbackFunction = pxCallback->pCallbackFunction;
                        ( void ) uxListRemove( &pxCallback->xListItem );
                        vPortFree( pxCallback );

                        if( listLIST_IS_EMPTY( &xCallbackList ) != pdFALSE )
                        {
                            /* The list of outstanding requests is empty. No need for periodic polling. */
                            vIPSetDnsTimerEnableState( pdFALSE );
                        }

                        xResult = pdTRUE;
                        break;
                    }
                }
            }
            ( void ) xTaskResumeAll();

            if( pCallbackFunction != NULL )
            {
                #if ( ipconfigUSE_IPv6 != 0 )
                    {
                        pCallbackFunction( pxSet->pcName, pvSearchID, pxAddress );
                    }
                #else
                    {
                        pCallbackFunction( pxSet->pcName, pvSearchID, ulIPAddress );
                    }
                #endif
            }

            return xResult;
        }

    #endif /* ipconfigDNS_USE_CALLBACKS == 1 */
/*-----------------------------------------------------------*/


    #if ( ipconfigDNS_USE_CALLBACKS == 1 )

/**
 * @brief Look-up the IP-address of a host.
 *
 * @param[in] pcName: The name of the node or device
 * @param[in] pcService: Ignored for now.
 * @param[in] pxHints: If not NULL: preferences. Can be used to indicate the preferred type if IP ( v4 or v6 ).
 * @param[out] ppxResult: An allocated struct, containing the results.
 *
 * @return Zero when the operation was successful, otherwise a negative errno value.
 */
        BaseType_t FreeRTOS_getaddrinfo( const char * pcName,                      /* The name of the node or device */
                                         const char * pcService,                   /* Ignored for now. */
                                         const struct freertos_addrinfo * pxHints, /* If not NULL: preferences. */
                                         struct freertos_addrinfo ** ppxResult )   /* An allocated struct, containing the results. */
        {
            /* Call the asynchronous version with NULL parameters. */
            return FreeRTOS_getaddrinfo_a( pcName, pcService, pxHints, ppxResult, NULL, NULL, 0U );
        }
    #endif /* ( ipconfigDNS_USE_CALLBACKS == 1 ) */
/*-----------------------------------------------------------*/

/**
 * @brief Internal function: allocate and initialise a new struct of type freertos_addrinfo.
 *
 * @param[in] pcName: the name of the host.
 * @param[in] xFamily: the type of IP-address: FREERTOS_AF_INET4 or FREERTOS_AF_INET6.
 * @param[in] pucAddress: The IP-address of the host.
 *
 * @return A pointer to the newly allocated struct, or NULL in case malloc failed..
 */
    static struct freertos_addrinfo * pxNew_AddrInfo( const char * pcName,
                                                      BaseType_t xFamily,
                                                      const uint8_t * pucAddress )
    {
        struct freertos_addrinfo * pxAddrInfo = NULL;
        void * pvBuffer;

        /* 'xFamily' might not be used when IPv6 is disabled. */
        ( void ) xFamily;
        pvBuffer = pvPortMalloc( sizeof( *pxAddrInfo ) );

        if( pvBuffer != NULL )
        {
            pxAddrInfo = ( struct freertos_addrinfo * ) pvBuffer;

            ( void ) memset( pxAddrInfo, 0, sizeof( *pxAddrInfo ) );
            pxAddrInfo->ai_canonname = pxAddrInfo->xPrivateStorage.ucName;
            ( void ) strncpy( pxAddrInfo->xPrivateStorage.ucName, pcName, sizeof( pxAddrInfo->xPrivateStorage.ucName ) );

            #if ( ipconfigUSE_IPv6 == 0 )
                pxAddrInfo->ai_addr = &( pxAddrInfo->xPrivateStorage.sockaddr4 );
            #else
                pxAddrInfo->ai_addr = ipCAST_PTR_TO_TYPE_PTR( sockaddr4_t, &( pxAddrInfo->xPrivateStorage.sockaddr6 ) );

                if( xFamily == ( BaseType_t ) FREERTOS_AF_INET6 )
                {
                    pxAddrInfo->ai_family = FREERTOS_AF_INET6;
                    pxAddrInfo->ai_addrlen = ipSIZE_OF_IPv6_ADDRESS;
                    ( void ) memcpy( pxAddrInfo->xPrivateStorage.sockaddr6.sin_addrv6.ucBytes, pucAddress, ipSIZE_OF_IPv6_ADDRESS );
                }
                else
            #endif /* ( ipconfigUSE_IPv6 == 0 ) */
            {
                /* ulChar2u32 reads from big-endian to host-endian. */
                uint32_t ulIPAddress = ulChar2u32( pucAddress );
                /* Translate to network-endian. */
                pxAddrInfo->ai_addr->sin_addr = FreeRTOS_htonl( ulIPAddress );
                pxAddrInfo->ai_family = FREERTOS_AF_INET4;
                pxAddrInfo->ai_addrlen = ipSIZE_OF_IPv4_ADDRESS;
            }
        }

        return pxAddrInfo;
    }
/*-----------------------------------------------------------*/

    #if ( ipconfigDNS_USE_CALLBACKS == 1 )

/**
 * @brief Asynchronous version of getaddrinfo().
 *
 * @param[in] pcName: The name of the node or device
 * @param[in] pcService: Ignored for now.
 * @param[in] pxHints: If not NULL: preferences. Can be used to indicate the preferred type if IP ( v4 or v6 ).
 * @param[out] ppxResult: An allocated struct, containing the results.
 * @param[in] pCallback: A user-defined function which will be called on completion, either when found or after a time-out.
 * @param[in] pvSearchID: A user provided void pointer that will be communicated on completion.
 * @param[in] uxTimeout: The maximum number of clock ticks that must be waited for a reply.
 *
 * @return Zero when the operation was successful, otherwise a negative errno value.
 */
        BaseType_t FreeRTOS_getaddrinfo_a( const char * pcName,                      /* The name of the node or device */
                                           const char * pcService,                   /* Ignored for now. */
                                           const struct freertos_addrinfo * pxHints, /* If not NULL: preferences. */
                                           struct freertos_addrinfo ** ppxResult,    /* An allocated struct, containing the results. */
                                           FOnDNSEvent pCallback,
                                           void * pvSearchID,
                                           TickType_t uxTimeout )
    #else

/**
 * @brief Look-up the IP-address of a host.
 *
 * @param[in] pcName: The name of the node or device
 * @param[in] pcService: Ignored for now.
 * @param[in] pxHints: If not NULL: preferences. Can be used to indicate the preferred type if IP ( v4 or v6 ).
 * @param[out] ppxResult: An allocated struct, containing the results.
 *
 * @return Zero when the operation was successful, otherwise a negative errno value.
 */
        BaseType_t FreeRTOS_getaddrinfo( const char * pcName,                      /* The name of the node or device */
                                         const char * pcService,                   /* Ignored for now. */
                                         const struct freertos_addrinfo * pxHints, /* If not NULL: preferences. */
                                         struct freertos_addrinfo ** ppxResult )   /* An allocated struct, containing the results. */
    #endif /* ipconfigDNS_USE_CALLBACKS == 1 */
    {
        BaseType_t xReturn = 0;
        uint32_t ulResult;
        BaseType_t xFamily = FREERTOS_AF_INET4;

        ( void ) pcService;
        ( void ) pxHints;

        if( ppxResult != NULL )
        {
            *( ppxResult ) = NULL;

            #if ( ipconfigUSE_IPv6 != 0 )
                if( pxHints != NULL )
                {
                    if( pxHints->ai_family == FREERTOS_AF_INET6 )
                    {
                        xFamily = FREERTOS_AF_INET6;
                    }
                    else if( pxHints->ai_family != FREERTOS_AF_INET4 )
                    {
                        xReturn = -pdFREERTOS_ERRNO_EINVAL;
                    }
                    else
                    {
                        /* This is FREERTOS_AF_INET4, carry on. */
                    }
                }
            #endif /* ( ipconfigUSE_IPv6 == 0 ) */

            #if ( ipconfigUSE_IPv6 != 0 )
                if( xReturn == 0 )
            #endif
            {
                #if ( ipconfigDNS_USE_CALLBACKS == 1 )
                    {
                        ulResult = prvPrepareLookup( pcName, ppxResult, xFamily, pCallback, pvSearchID, uxTimeout );
                    }
                #else
                    {
                        ulResult = prvPrepareLookup( pcName, ppxResult, xFamily );
                    }
                #endif /* ( ipconfigDNS_USE_CALLBACKS == 1 ) */

                if( ulResult != 0U )
                {
                    if( *( ppxResult ) != NULL )
                    {
                        xReturn = 0;
                    }
                    else
                    {
                        xReturn = -pdFREERTOS_ERRNO_ENOMEM;
                    }
                }
                else
                {
                    xReturn = -pdFREERTOS_ERRNO_ENOENT;
                }
            }
        }
        else
        {
            xReturn = -pdFREERTOS_ERRNO_EINVAL;
        }

        return xReturn;
    }
/*-----------------------------------------------------------*/

/**
 * @brief Free a chain of structs of type 'freertos_addrinfo'.
 *
 * @param[in] pxInfo: The first find result.
 */
    void FreeRTOS_freeaddrinfo( struct freertos_addrinfo * pxInfo )
    {
        struct freertos_addrinfo * pxNext;
        struct freertos_addrinfo * pxIterator = pxInfo;

        configASSERT( pxLastInfo != pxInfo );

        while( pxIterator != NULL )
        {
            pxNext = pxIterator->ai_next;
            vPortFree( pxIterator );
            pxIterator = pxNext;
        }

        pxLastInfo = NULL;
    }
/*-----------------------------------------------------------*/

    #if ( ipconfigDNS_USE_CALLBACKS == 0 )

/**
 * @brief Get the IPv4 address corresponding to the given hostname. The function
 *        will block until there is an answer, or until a time-out is reached.
 *
 * @param[in] pcHostName: The hostname whose IP address is being queried.
 *
 * @return The IPv4 address corresponding to the hostname.
 */
        uint32_t FreeRTOS_gethostbyname( const char * pcHostName )
        {
            return prvPrepareLookup( pcHostName, NULL, FREERTOS_AF_INET4 );
        }
    #else

/**
 * @brief Get the IPv4 address corresponding to the given hostname. The search will
 *        be done asynchronously.
 *
 * @param[in] pcHostName: The hostname whose IP address is being queried.
 * @param[in] pCallback: The callback function which will be called upon DNS response.
 * @param[in] pvSearchID: Search ID for the callback function.
 * @param[in] uxTimeout: Timeout for the callback function.
 *
 * @return The IP-address corresponding to the hostname.
 */
        uint32_t FreeRTOS_gethostbyname_a( const char * pcHostName,
                                           FOnDNSEvent pCallback,
                                           void * pvSearchID,
                                           TickType_t uxTimeout )
        {
            uint32_t ulResult;
            struct freertos_addrinfo * pxAddressInfo = NULL;

            ulResult = prvPrepareLookup( pcHostName, &( pxAddressInfo ), FREERTOS_AF_INET4, pCallback, pvSearchID, uxTimeout );

            if( pxAddressInfo != NULL )
            {
                FreeRTOS_freeaddrinfo( pxAddressInfo );
            }

            return ulResult;
        }
    #endif /* ( ipconfigDNS_USE_CALLBACKS == 0 ) */

    #if ( ipconfigUSE_DNS_CACHE == 1 )
        static uint32_t prvPrepare_CacheLookup( const char * pcHostName,
                                                BaseType_t xFamily,
                                                struct freertos_addrinfo ** ppxAddressInfo )
        {
            uint32_t ulIPAddress = 0U;

            #if ( ipconfigUSE_IPv6 != 0 )
                if( xFamily == FREERTOS_AF_INET6 )
                {
                    IPv46_Address_t xIPv46_Address;
                    BaseType_t xFound;

                    xIPv46_Address.xIs_IPv6 = pdTRUE;
                    xFound = prvProcessDNSCache( pcHostName, &( xIPv46_Address ), 0, pdTRUE, ppxAddressInfo );

                    if( xFound != 0 )
                    {
                        if( ( ppxAddressInfo != NULL ) && ( *( ppxAddressInfo ) != NULL ) )
                        {
                            struct freertos_sockaddr6 * sockaddr6 = ipCAST_PTR_TO_TYPE_PTR( sockaddr6_t, ( *( ppxAddressInfo ) )->ai_addr );

                            ( void ) sockaddr6;

                            /* This function returns either a valid IPv4 address, or
                             * in case of an IPv6 lookup, it will return a non-zero */
                            ulIPAddress = 1U;
                        }
                    }
                    else
                    {
                        /* prvGetHostByName will be called to start a DNS lookup. */
                    }
                }
                else
            #endif /* ( ipconfigUSE_IPv6 != 0 ) */
            {
                IPv46_Address_t xIPv46_Address;
                BaseType_t xFound;

                #if ( ipconfigUSE_IPv6 != 0 )
                    xIPv46_Address.xIs_IPv6 = pdFALSE;
                #endif /* ( ipconfigUSE_IPv6 != 0 ) */
                xFound = prvProcessDNSCache( pcHostName, &( xIPv46_Address ), 0, pdTRUE, ppxAddressInfo );

                if( xFound != 0 )
                {
                    if( ( ppxAddressInfo != NULL ) && ( *( ppxAddressInfo ) != NULL ) )
                    {
                        struct freertos_sockaddr * sockaddr = ( *( ppxAddressInfo ) )->ai_addr;

                        ulIPAddress = sockaddr->sin_addr;
                    }
                }
                else
                {
                    /* prvGetHostByName will be called to start a DNS lookup. */
                }
            }

            return ulIPAddress;
        }
    #endif /* ( ipconfigUSE_DNS_CACHE == 1 ) */

    #if ( ipconfigINCLUDE_FULL_INET_ADDR == 1 )

/**
 * @brief See if pcHostName contains a valid IPv4 or IPv6 IP-address.
 *
 * @param[in] pcHostName: The name to be looked up
 * @param[in] xFamily: the IP-type, either FREERTOS_AF_INET4 or FREERTOS_AF_INET6.
 * @param[in] ppxAddressInfo: A pointer to a pointer where the find results will
 *                            be stored.
 * @return Either 0 or an IP=address.
 */
        static uint32_t prvPrepare_ReadIPAddress( const char * pcHostName,
                                                  BaseType_t xFamily,
                                                  struct freertos_addrinfo ** ppxAddressInfo )
        {
            uint32_t ulIPAddress = 0U;

            /* Check if the hostname given is actually an IP-address. */
            #if ( ipconfigUSE_IPv6 != 0 )
                if( xFamily == FREERTOS_AF_INET6 )
                {
                    IPv6_Address_t xAddress_IPv6;
                    BaseType_t xResult;

                    /* ulIPAddress does not represent an IPv4 address here. It becomes non-zero when the look-up succeeds. */
                    xResult = FreeRTOS_inet_pton6( pcHostName, xAddress_IPv6.ucBytes );

                    if( xResult == 1 )
                    {
                        /* This function returns either a valid IPv4 address, or
                         * in case of an IPv6 lookup, it will return a non-zero */
                        ulIPAddress = 1U;

                        if( ppxAddressInfo != NULL )
                        {
                            *( ppxAddressInfo ) = pxNew_AddrInfo( pcHostName, FREERTOS_AF_INET6, xAddress_IPv6.ucBytes );
                        }
                    }
                }
                else
            #endif /* ipconfigUSE_IPv6 */
            {
                ulIPAddress = FreeRTOS_inet_addr( pcHostName );

                if( ( ulIPAddress != 0U ) && ( ppxAddressInfo != NULL ) )
                {
                    uint8_t * ucBytes = ( uint8_t * ) &( ulIPAddress );

                    *( ppxAddressInfo ) = pxNew_AddrInfo( pcHostName, FREERTOS_AF_INET4, ucBytes );
                }
            }

            return ulIPAddress;
        }
    #endif /* ( ipconfigINCLUDE_FULL_INET_ADDR == 1 ) */

    #if ( ipconfigDNS_USE_CALLBACKS == 1 )

/**
 * @brief Check if hostname is already known. If not, call prvGetHostByName() to send a DNS request.
 *
 * @param[in] pcHostName: The hostname whose IP address is being queried.
 * @param[in] ppxAddressInfo: A pointer to a pointer where the find results will
 *                            be stored.
 * @param[in] xFamily: Either FREERTOS_AF_INET4 or FREERTOS_AF_INET6.
 * @param[in] pCallbackFunction: The callback function which will be called upon DNS response.
 * @param[in] pvSearchID: Search ID for the callback function.
 * @param[in] uxTimeout: Timeout for the callback function.
 *
 * @return The IP-address corresponding to the hostname.
 */
        static uint32_t prvPrepareLookup( const char * pcHostName,
                                          struct freertos_addrinfo ** ppxAddressInfo,
                                          BaseType_t xFamily,
                                          FOnDNSEvent pCallbackFunction,
                                          void * pvSearchID,
                                          TickType_t uxTimeout )
    #else

/**
 * @brief Check if hostname is already known. If not, call prvGetHostByName() to send a DNS request.
 *        This function will block to wait for a reply.
 *
 * @param[in] pcHostName: The hostname whose IP address is being queried.
 * @param[in] ppxAddressInfo: A pointer to a pointer where the find results will
 *                            be stored.
 * @param[in] xFamily: Either FREERTOS_AF_INET4 or FREERTOS_AF_INET6.
 *
 * @return The IP-address corresponding to the hostname.
 */
        static uint32_t prvPrepareLookup( const char * pcHostName,
                                          struct freertos_addrinfo ** ppxAddressInfo,
                                          BaseType_t xFamily )
    #endif /* ( ipconfigDNS_USE_CALLBACKS == 1 ) */
    {
        uint32_t ulIPAddress = 0U;
        TickType_t uxReadTimeOut_ticks = ipconfigDNS_RECEIVE_BLOCK_TIME_TICKS;

/* Generate a unique identifier for this query. Keep it in a local variable
 * as gethostbyname() may be called from different threads */
        BaseType_t xHasRandom = pdFALSE;
        TickType_t uxIdentifier = 0U;

        #if ( ipconfigUSE_DNS_CACHE != 0 )
            BaseType_t xLengthOk = pdFALSE;
        #endif

        #if ( ipconfigUSE_DNS_CACHE != 0 )
            {
                if( pcHostName != NULL )
                {
                    size_t uxLength = strlen( pcHostName ) + 1U;

                    if( uxLength <= ipconfigDNS_CACHE_NAME_LENGTH )
                    {
                        /* The name is not too long. */
                        xLengthOk = pdTRUE;
                    }
                    else
                    {
                        FreeRTOS_printf( ( "prvPrepareLookup: name is too long ( %lu > %lu )\n",
                                           ( uint32_t ) uxLength,
                                           ( uint32_t ) ipconfigDNS_CACHE_NAME_LENGTH ) );
                    }
                }
            }

            if( ( pcHostName != NULL ) && ( xLengthOk != pdFALSE ) )
        #else /* if ( ipconfigUSE_DNS_CACHE != 0 ) */
            if( pcHostName != NULL )
        #endif /* ( ipconfigUSE_DNS_CACHE != 0 ) */
        {
            /* If the supplied hostname is an IP address, convert it to uint32_t
             * and return. */
            #if ( ipconfigINCLUDE_FULL_INET_ADDR == 1 )
                {
                    ulIPAddress = prvPrepare_ReadIPAddress( pcHostName, xFamily, ppxAddressInfo );
                }
            #endif /* ipconfigINCLUDE_FULL_INET_ADDR == 1 */

            /* If a DNS cache is used then check the cache before issuing another DNS
             * request. */
            #if ( ipconfigUSE_DNS_CACHE == 1 )
                if( ulIPAddress == 0U )
                {
                    ulIPAddress = prvPrepare_CacheLookup( pcHostName, xFamily, ppxAddressInfo );
                }
            #endif /* ipconfigUSE_DNS_CACHE == 1 */

            /* Generate a unique identifier. */
            if( ulIPAddress == 0U )
            {
                uint32_t ulNumber = 0U;

                xHasRandom = xApplicationGetRandomNumber( &( ulNumber ) );
                /* DNS identifiers are 16-bit. */
                uxIdentifier = ( TickType_t ) ( ulNumber & 0xffffU );
            }

            #if ( ipconfigDNS_USE_CALLBACKS == 1 )
                {
                    if( pCallbackFunction != NULL )
                    {
                        if( ulIPAddress == 0U )
                        {
                            /* The user has provided a callback function, so do not block on recvfrom() */
                            if( xHasRandom != pdFALSE )
                            {
                                uxReadTimeOut_ticks = 0;
                                #if ( ipconfigUSE_IPv6 != 0 )
                                    {
                                        vDNSSetCallBack( pcHostName, pvSearchID, pCallbackFunction, uxTimeout, ( TickType_t ) uxIdentifier, ( xFamily == FREERTOS_AF_INET6 ) ? pdTRUE : pdFALSE );
                                    }
                                #else
                                    {
                                        vDNSSetCallBack( pcHostName, pvSearchID, pCallbackFunction, uxTimeout, ( TickType_t ) uxIdentifier );
                                    }
                                #endif /* ( ipconfigUSE_IPv6 != 0 ) */
                            }
                        }
                        else if( ppxAddressInfo != NULL )
                        {
                            /* The IP address is known, do the call-back now. */
                            pCallbackFunction( pcHostName, pvSearchID, *( ppxAddressInfo ) );
                        }
                    }
                }
            #endif /* if ( ipconfigDNS_USE_CALLBACKS == 1 ) */

            if( ( ulIPAddress == 0U ) && ( xHasRandom != pdFALSE ) )
            {
                ulIPAddress = prvGetHostByName( pcHostName, uxIdentifier, uxReadTimeOut_ticks, ppxAddressInfo, xFamily );
            }
        }

        return ulIPAddress;
    }
/*-----------------------------------------------------------*/

    #if ( ipconfigUSE_IPv6 != 0 )
        static void prvIncreaseDNS6Index( NetworkEndPoint_t * pxEndPoint )
        {
            uint8_t ucIndex = pxEndPoint->ipv6_settings.ucDNSIndex;

            ucIndex++;

            if( ucIndex >= ( uint8_t ) ipconfigENDPOINT_DNS_ADDRESS_COUNT )
            {
                ucIndex = 0U;
            }

            pxEndPoint->ipv6_settings.ucDNSIndex = ucIndex;
        }
    #endif /* ( ipconfigUSE_IPv6 != 0 ) */

/**
 * @brief Increment the field 'ucDNSIndex', which is an index in the array
 *        of DNS addresses.
 *
 * @param[in] pxEndPoint: The end-point of which the DNS index should be
 *                        incremented.
 */
    static void prvIncreaseDNS4Index( NetworkEndPoint_t * pxEndPoint )
    {
        uint8_t ucIndex = pxEndPoint->ipv4_settings.ucDNSIndex;

        ucIndex++;

        if( ucIndex >= ( uint8_t ) ipconfigENDPOINT_DNS_ADDRESS_COUNT )
        {
            ucIndex = 0U;
        }

        pxEndPoint->ipv4_settings.ucDNSIndex = ucIndex;
    }
/*-----------------------------------------------------------*/

/**
 * @brief Get an IP address ( IPv4 or IPv6 ) of a DNS server.
 * @param[out] pxAddress: Variable to store the address found.
 * @param[in] pcHostName: use to check if it contains a dot ( DNS ), or not ( LLMNR ).
 * @return The end-point that holds the DNS address.
 */

    static NetworkEndPoint_t * prvGetDNSAddress( struct freertos_sockaddr * pxAddress,
                                                 const char * pcHostName )
    {
        NetworkEndPoint_t * pxEndPoint = NULL;
        BaseType_t xNeed_Endpoint = pdFALSE;

        /* Make sure all fields of the 'sockaddr' are cleared. */
        ( void ) memset( ( void * ) pxAddress, 0, sizeof( *pxAddress ) );

        /* And set the address type to IPv4.
         * It may change to IPv6 in case an IPv6 DNS server will be used. */
        pxAddress->sin_family = FREERTOS_AF_INET;

        /* 'sin_len' doesn't really matter, 'sockaddr' and 'sockaddr6'
         * have the same size. */
        pxAddress->sin_len = ( uint8_t ) sizeof( struct freertos_sockaddr );
        /* Use the DNS port by default, this may be changed later. */
        pxAddress->sin_port = dnsDNS_PORT;

        /* If LLMNR is being used then determine if the host name includes a '.' -
         * if not then LLMNR can be used as the lookup method. */
        /* For local resolution, mDNS uses names ending with the string ".local" */
        BaseType_t bHasDot = pdFALSE;
        BaseType_t bHasLocal = pdFALSE;
        char * pcDot = strchr( pcHostName, '.' );

        if( pcDot != NULL )
        {
            bHasDot = pdTRUE;

            if( strcmp( pcDot, ".local" ) == 0 )
            {
                bHasLocal = pdTRUE;
            }
            else
            {
                /* a DNS look-up of a public URL with at least one dot. */
            }
        }

        /* Is this a local lookup? */
        if( ( bHasDot == pdFALSE ) || ( bHasLocal == pdTRUE ) )
        {
            #if ( ipconfigUSE_MDNS == 1 )
                {
                    if( bHasLocal )
                    {
                        /* Looking up a name like "mydevice.local".
                         * Use mDNS addresses. */
                        pxAddress->sin_addr = ipMDNS_IP_ADDRESS; /* Is in network byte order. */
                        pxAddress->sin_port = ipMDNS_PORT;
                        pxAddress->sin_port = FreeRTOS_ntohs( pxAddress->sin_port );
                        xNeed_Endpoint = pdTRUE;
                        #if ( ipconfigUSE_IPv6 != 0 )
                            if( xDNS_IP_Preference == xPreferenceIPv6 )
                            {
                                sockaddr6_t * pxAddressV6 = ipCAST_PTR_TO_TYPE_PTR( sockaddr6_t, pxAddress );
                                memcpy( pxAddressV6->sin_addrv6.ucBytes,
                                        ipMDNS_IP_ADDR_IPv6.ucBytes,
                                        ipSIZE_OF_IPv6_ADDRESS );
                                pxAddress->sin_family = FREERTOS_AF_INET6;
                            }
                        #endif
                    }
                }
            #endif /* if ( ipconfigUSE_MDNS == 1 ) */
            #if ( ipconfigUSE_LLMNR == 1 )
                {
                    /* The hostname doesn't have a dot. */
                    if( bHasDot == pdFALSE )
                    {
                        /* Use LLMNR addressing. */
                        pxAddress->sin_addr = ipLLMNR_IP_ADDR; /* Is in network byte order. */
                        pxAddress->sin_port = ipLLMNR_PORT;
                        pxAddress->sin_port = FreeRTOS_ntohs( pxAddress->sin_port );
                        xNeed_Endpoint = pdTRUE;
                        #if ( ipconfigUSE_IPv6 != 0 )
                            sockaddr6_t * pxAddressV6 = ipCAST_PTR_TO_TYPE_PTR( sockaddr6_t, pxAddress );

                            if( xDNS_IP_Preference == xPreferenceIPv6 )
                            {
                                memcpy( pxAddressV6->sin_addrv6.ucBytes,
                                        ipLLMNR_IP_ADDR_IPv6.ucBytes,
                                        ipSIZE_OF_IPv6_ADDRESS );
                                pxAddress->sin_family = FREERTOS_AF_INET6;
                            }
                        #endif
                    }
                }
            #endif /* if ( ipconfigUSE_LLMNR == 1 ) */

            if( xNeed_Endpoint == pdTRUE )
            {
                for( pxEndPoint = FreeRTOS_FirstEndPoint( NULL );
                     pxEndPoint != NULL;
                     pxEndPoint = FreeRTOS_NextEndPoint( NULL, pxEndPoint ) )
                {
                    #if ( ipconfigUSE_IPv6 != 0 )
                        if( xDNS_IP_Preference == xPreferenceIPv6 )
                        {
                            if( ENDPOINT_IS_IPv6( pxEndPoint ) )
                            {
                                break;
                            }
                        }
                        else
                        {
                            if( ENDPOINT_IS_IPv4( pxEndPoint ) )
                            {
                                break;
                            }
                        }
                    #else /* if ( ipconfigUSE_IPv6 != 0 ) */
                        /* IPv6 is not included, so all end-points are IPv4. */
                        break;
                    #endif /* if ( ipconfigUSE_IPv6 != 0 ) */
                }
            }
        }
        else
        {
            /* Look for an end-point that has defined a DNS server address. */
            for( pxEndPoint = FreeRTOS_FirstEndPoint( NULL );
                 pxEndPoint != NULL;
                 pxEndPoint = FreeRTOS_NextEndPoint( NULL, pxEndPoint ) )
            {
                #if ( ipconfigUSE_IPv6 != 0 )
                    if( ENDPOINT_IS_IPv6( pxEndPoint ) )
                    {
                        uint8_t ucIndex = pxEndPoint->ipv6_settings.ucDNSIndex;
                        uint8_t * ucBytes = pxEndPoint->ipv6_settings.xDNSServerAddresses[ ucIndex ].ucBytes;

                        /* Test if the DNS entry is in used. */
                        if( ( ucBytes[ 0 ] != 0U ) && ( ucBytes[ 1 ] != 0U ) )
                        {
                            struct freertos_sockaddr6 * pxAddress6 = ( struct freertos_sockaddr6 * ) pxAddress;

                            pxAddress->sin_family = FREERTOS_AF_INET6;
                            pxAddress->sin_len = ( uint8_t ) sizeof( struct freertos_sockaddr6 );
                            ( void ) memcpy( pxAddress6->sin_addrv6.ucBytes,
                                             pxEndPoint->ipv6_settings.xDNSServerAddresses[ ucIndex ].ucBytes,
                                             ipSIZE_OF_IPv6_ADDRESS );
                            break;
                        }
                    }
                    else
                #endif /* if ( ipconfigUSE_IPv6 != 0 ) */
                {
                    uint8_t ucIndex = pxEndPoint->ipv4_settings.ucDNSIndex;
                    uint32_t ulIPAddress = pxEndPoint->ipv4_settings.ulDNSServerAddresses[ ucIndex ];

                    if( ( ulIPAddress != 0U ) && ( ulIPAddress != ipBROADCAST_IP_ADDRESS ) )
                    {
                        pxAddress->sin_addr = ulIPAddress;
                        break;
                    }
                }
            }
        }

        return pxEndPoint;
    }
/*-----------------------------------------------------------*/

/**
 * @brief Prepare and send a message to a DNS server.  'uxReadTimeOut_ticks' will be passed as
 * zero, in case the user has supplied a call-back function.
 *
 * @param[in] pcHostName: The hostname for which an IP address is required.
 * @param[in] uxIdentifier: Identifier to send in the DNS message.
 * @param[in] uxReadTimeOut_ticks: The timeout in ticks for waiting. In case the user has supplied
 *                                 a call-back function, this value should be zero.
 * @param[in,out] ppxAddressInfo: A pointer to a pointer where the find results
 *                will be stored.
 * @param[in] xFamily: Either FREERTOS_AF_INET4 or FREERTOS_AF_INET6.
 * @return The IPv4 IP address for the hostname being queried. It will be zero if there is no reply.
 */
    static uint32_t prvGetHostByName( const char * pcHostName,
                                      TickType_t uxIdentifier,
                                      TickType_t uxReadTimeOut_ticks,
                                      struct freertos_addrinfo ** ppxAddressInfo,
                                      BaseType_t xFamily )
    {
        struct freertos_sockaddr xAddress;
        Socket_t xDNSSocket;
        uint32_t ulIPAddress = 0U;
        socklen_t uxAddressLength = sizeof( struct freertos_sockaddr );
        BaseType_t xAttempt;
        int32_t lBytes;
        size_t uxPayloadLength;

        /* Two is added at the end for the count of characters in the first
         * subdomain part and the string end byte.
         * The two shorts are described in 'DNSTail_t'. */
        size_t uxExpectedPayloadLength = sizeof( DNSMessage_t ) + strlen( pcHostName ) + sizeof( uint16_t ) + sizeof( uint16_t ) + 2U;
        TickType_t uxWriteTimeOut_ticks = ipconfigDNS_SEND_BLOCK_TIME_TICKS;
        UBaseType_t uxHostType;
        TickType_t uxReadTicks = uxReadTimeOut_ticks;

        if( uxReadTicks < 50U )
        {
            uxReadTicks = 50U;
        }

        #if ( ipconfigUSE_IPv6 != 0 )
            if( xFamily == FREERTOS_AF_INET6 )
            {
                /* Note that 'dnsTYPE_ANY_HOST' could be used here as well,
                 * but for testing, we want an IPv6 address. */
                uxHostType = dnsTYPE_AAAA_HOST;
                uxExpectedPayloadLength += ipSIZE_OF_IPv6_ADDRESS;
            }
            else
        #endif /* ( ipconfigUSE_IPv6 != 0 ) */
        {
            ( void ) xFamily;
            uxHostType = dnsTYPE_A_HOST;
        }

        xDNSSocket = prvCreateDNSSocket();

        if( xDNSSocket != NULL )
        {
            /* Ideally we should check for the return value. But since we are passing
             * correct parameters, and xDNSSocket is != NULL, the return value is
             * going to be '0' i.e. success. Thus, return value is discarded */
            ( void ) FreeRTOS_setsockopt( xDNSSocket, 0, FREERTOS_SO_SNDTIMEO, &( uxWriteTimeOut_ticks ), sizeof( TickType_t ) );
            ( void ) FreeRTOS_setsockopt( xDNSSocket, 0, FREERTOS_SO_RCVTIMEO, &( uxReadTicks ), sizeof( TickType_t ) );

            for( xAttempt = 0; xAttempt < ipconfigDNS_REQUEST_ATTEMPTS; xAttempt++ )
            {
                size_t uxHeaderBytes;
                NetworkBufferDescriptor_t * pxNetworkBuffer;
                uint8_t * pucUDPPayloadBuffer = NULL, * pucReceiveBuffer;
                NetworkEndPoint_t * pxEndPoint;

                pxEndPoint = prvGetDNSAddress( &( xAddress ), pcHostName );

                if( pxEndPoint == NULL )
                {
                    FreeRTOS_printf( ( "Can not find a DNS address, along with an end-point.\n" ) );
                    /* No endpoint was found that defines a DNS address. */
                    break;
                }

                if( xAttempt == 0 )
                {
                    /* Bind the client socket to a random port number. */
                    uint16_t usPort = 0U;
                    #if ( ipconfigUSE_MDNS == 1 )
                        if( xAddress.sin_port == FreeRTOS_htons( ipMDNS_PORT ) )
                        {
                            /* For a mDNS lookup, bind to the mDNS port 5353. */
                            usPort = FreeRTOS_htons( ipMDNS_PORT );
                        }
                    #endif

                    if( prvBindDNSSocket( xDNSSocket, usPort ) != 0 )
                    {
                        FreeRTOS_printf( ( "DNS bind to %u failed\n", FreeRTOS_ntohs( usPort ) ) );
                        break;
                    }
                }

                /* Calculate the size of the headers. */
                #if ( ipconfigUSE_IPv6 != 0 )
                    if( xAddress.sin_family == FREERTOS_AF_INET6 )
                    {
                        uxHeaderBytes = ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv6_HEADER + ipSIZE_OF_UDP_HEADER;
                    }
                    else
                #endif
                {
                    uxHeaderBytes = ipSIZE_OF_ETH_HEADER + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_UDP_HEADER;
                }

                {
                    char pcBuffer[ 41 ];
                    #if ( ipconfigUSE_IPv6 != 0 )
                        if( xAddress.sin_family == FREERTOS_AF_INET6 )
                        {
                            struct freertos_sockaddr6 * pxSockaddr6 = ( struct freertos_sockaddr6 * ) &( xAddress );
                            FreeRTOS_inet_ntop6( pxSockaddr6->sin_addrv6.ucBytes,
                                                 pcBuffer,
                                                 sizeof( pcBuffer ) );
                        }
                        else
                    #endif
                    {
                        FreeRTOS_inet_ntop4( ( void * ) &( xAddress.sin_addr ),
                                             pcBuffer,
                                             sizeof( pcBuffer ) );
                    }

                    FreeRTOS_printf( ( "DNS-%c lookup: \"%s\" DNS at %s\n",
                                       ( xFamily == FREERTOS_AF_INET4 ) ? '4' : '6',
                                       pcHostName,
                                       pcBuffer ) );
                }

                pxNetworkBuffer = pxGetNetworkBufferWithDescriptor( uxHeaderBytes + uxExpectedPayloadLength, 0U );

                if( pxNetworkBuffer == NULL )
                {
                    FreeRTOS_printf( ( "prvGetHostByName: No network buffer\n" ) );
                    break;
                }

                /* A two-step conversion to conform to MISRA. */
                size_t uxIndex = ipUDP_PAYLOAD_IP_TYPE_OFFSET;
                BaseType_t xIndex = ( BaseType_t ) uxIndex;
                pucUDPPayloadBuffer = &( pxNetworkBuffer->pucEthernetBuffer[ uxHeaderBytes ] );

                /* Later when translating form UDP payload to a Network Buffer,
                 * it is important to know whether this is an IPv4 packet. */
                #if ( ipconfigUSE_IPv6 != 0 )
                    if( xAddress.sin_family == FREERTOS_AF_INET6 )
                    {
                        pucUDPPayloadBuffer[ -xIndex ] = ( uint8_t ) ipTYPE_IPv6;
                    }
                    else
                #endif
                {
                    pucUDPPayloadBuffer[ -xIndex ] = ( uint8_t ) ipTYPE_IPv4;
                }

                /* Create the message in the obtained buffer. */
                uxPayloadLength = prvCreateDNSMessage( pucUDPPayloadBuffer, pcHostName, uxIdentifier, uxHostType );

                iptraceSENDING_DNS_REQUEST();

                /* ipLLMNR_IP_ADDR is in network byte order. */
                if( ( xAddress.sin_addr == ipLLMNR_IP_ADDR ) || ( xAddress.sin_addr == ipMDNS_IP_ADDRESS ) )
                {
                    /* Use LLMNR addressing. */
                    ( ipCAST_PTR_TO_TYPE_PTR( DNSMessage_t, pucUDPPayloadBuffer ) )->usFlags = 0;
                }

                ulIPAddress = 0U;
                BaseType_t xSendResult = FreeRTOS_sendto( xDNSSocket, pucUDPPayloadBuffer, uxPayloadLength, FREERTOS_ZERO_COPY, &xAddress, sizeof( xAddress ) );

                if( xSendResult <= 0 )
                {
                    /* The message was not sent so the stack will not be
                     * releasing the zero copy - it must be released here. */
                    vReleaseNetworkBufferAndDescriptor( pxNetworkBuffer );
                    break;
                }

                struct freertos_sockaddr xRecvAddress;
                /* Wait for the reply. */
                /* FREERTOS_ZERO_COPY: passing the address of a character pointer to avoid a copy. */
                lBytes = FreeRTOS_recvfrom( xDNSSocket, &pucReceiveBuffer, 0, FREERTOS_ZERO_COPY, &( xRecvAddress ), &uxAddressLength );

                if( ( lBytes == -pdFREERTOS_ERRNO_EWOULDBLOCK ) && ( pxEndPoint != NULL ) )
                {
                    /* This search timed out, next time try with a different DNS. */
                    #if ( ipconfigUSE_IPv6 != 0 )
                        if( xRecvAddress.sin_family == FREERTOS_AF_INET6 )
                        {
                            prvIncreaseDNS6Index( pxEndPoint );
                        }
                        else
                    #endif
                    {
                        prvIncreaseDNS4Index( pxEndPoint );
                    }
                }
                else if( lBytes > 0 )
                {
                    BaseType_t xExpected;
                    const DNSMessage_t * pxDNSMessageHeader = ipCAST_CONST_PTR_TO_CONST_TYPE_PTR( DNSMessage_t, pucReceiveBuffer );

                    #if ( ipconfigUSE_MDNS == 1 )
                        if( FreeRTOS_ntohs( xRecvAddress.sin_port ) == ipMDNS_PORT ) /* mDNS port 5353. */
                        {
                            /* In mDNS, the query ID field is ignored. */
                            xExpected = pdTRUE;
                        }
                        else
                    #endif /* if ( ipconfigUSE_MDNS == 1 ) */
                    {
                        /* See if the identifiers match. */
                        xExpected = ( uxIdentifier == ( TickType_t ) pxDNSMessageHeader->usIdentifier ) ? pdTRUE : pdFALSE;
                    }

                    /* The reply was received.  Process it. */
                    #if ( ipconfigDNS_USE_CALLBACKS == 0 )

                        /* It is useless to analyse the unexpected reply
                         * unless asynchronous look-ups are enabled. */
                        if( xExpected != pdFALSE )
                    #endif /* ipconfigDNS_USE_CALLBACKS == 0 */
                    {
                        /* IPv4: 'ulIPAddress' will contain the IP-address of the host, or zero.
                         * IPv6: 'ulIPAddress' will be non-zero, to indicated that an IPv6
                         * address was found. */
                        ulIPAddress = prvParseDNSReply( pucReceiveBuffer, ( size_t ) lBytes, ppxAddressInfo, xExpected, xAddress.sin_port );
                    }

                    /* Finished with the buffer.  The zero copy interface
                     * is being used, so the buffer must be freed by the
                     * task. */
                    FreeRTOS_ReleaseUDPPayloadBuffer( pucReceiveBuffer );

                    if( ulIPAddress != 0U )
                    {
                        /* All done. */
                        break;
                    }
                }
                else
                {
                    /* No data were received. */
                }

                if( lBytes <= 0 )
                {
                    break;
                }

                /* The first send may not succeed if an ARP request is sent.
                * Only the second will succeed. So send at least 2 times. */
                if( ( uxReadTimeOut_ticks == 0U ) && ( xAttempt > 0 ) )
                {
                    /* This DNS lookup is asynchronous, using a call-back:
                     * send the request only once. */
                    break;
                }
            }     /* for( xAttempt = 0; xAttempt < ipconfigDNS_REQUEST_ATTEMPTS; xAttempt++ ) */

            /* Finished with the socket. */
            ( void ) FreeRTOS_closesocket( xDNSSocket );
        }     /* if( xDNSSocket != NULL ) */

        return ulIPAddress;
    }
/*-----------------------------------------------------------*/

/**
 * @brief Create the DNS message in the zero copy buffer passed in the first parameter.
 *
 * @param[in,out] pucUDPPayloadBuffer: The zero copy buffer where the DNS message will be created.
 * @param[in] pcHostName: Hostname to be looked up.
 * @param[in] uxIdentifier: The identifier to be added to the DNS message.
 * @param[in] uxHostType: dnsTYPE_A_HOST ( IPv4 ) or dnsTYPE_AAA_HOST ( IPv6 ).
 *
 * @return Total size of the generated message, which is the space from the last written byte
 *         to the beginning of the buffer.
 */
    static size_t prvCreateDNSMessage( uint8_t * pucUDPPayloadBuffer,
                                       const char * pcHostName,
                                       TickType_t uxIdentifier,
                                       UBaseType_t uxHostType )
    {
        DNSMessage_t * pxDNSMessageHeader;
        size_t uxStart, uxIndex;
        uint8_t * pucTail;
        static const DNSMessage_t xDefaultPartDNSHeader =
        {
            0,                     /* The identifier will be overwritten. */
            dnsOUTGOING_FLAGS,     /* Flags set for standard query. */
            dnsONE_QUESTION,       /* One question is being asked. */
            0,                     /* No replies are included. */
            0,                     /* No authorities. */
            0                      /* No additional authorities. */
        };

/* memcpy() helper variables for MISRA Rule 21.15 compliance*/
        const void * pvCopySource;
        void * pvCopyDest;

        /* Although both pointers have been checked already, some extra
         * asserts are added to help the CBMC proofs.. */
        configASSERT( pucUDPPayloadBuffer != NULL );
        configASSERT( pcHostName != NULL );

        /* Copy in the const part of the header. Intentionally using different
         * pointers with memcpy() to put the information in to correct place. */

        /*
         * Use helper variables for memcpy() to remain
         * compliant with MISRA Rule 21.15.  These should be
         * optimized away.
         */
        pvCopySource = &xDefaultPartDNSHeader;
        pvCopyDest = pucUDPPayloadBuffer;
        ( void ) memcpy( pvCopyDest, pvCopySource, sizeof( xDefaultPartDNSHeader ) );

        /* Write in a unique identifier. Cast the Payload Buffer to DNSMessage_t
         * to easily access fields of the DNS Message. */
        pxDNSMessageHeader = ipCAST_PTR_TO_TYPE_PTR( DNSMessage_t, pucUDPPayloadBuffer );
        pxDNSMessageHeader->usIdentifier = ( uint16_t ) uxIdentifier;

        /* Create the resource record at the end of the header.  First
         * find the end of the header. */
        uxStart = sizeof( xDefaultPartDNSHeader );

        /* Leave a gap for the first length byte. */
        uxIndex = uxStart + 1U;

        /* Copy in the host name. */
        ( void ) strcpy( ( char * ) &( pucUDPPayloadBuffer[ uxIndex ] ), pcHostName );

        /* Walk through the string to replace the '.' characters with byte
         * counts.  pucStart holds the address of the byte count.  Walking the
         * string starts after the byte count position. */
        uxIndex = uxStart;

        do
        {
            size_t uxLength;

            /* Skip the length byte. */
            uxIndex++;

            while( ( pucUDPPayloadBuffer[ uxIndex ] != ( uint8_t ) 0U ) &&
                   ( pucUDPPayloadBuffer[ uxIndex ] != ( uint8_t ) ASCII_BASELINE_DOT ) )
            {
                uxIndex++;
            }

            /* Fill in the byte count, then move the pucStart pointer up to
             * the found byte position. */
            uxLength = uxIndex - ( uxStart + 1U );
            pucUDPPayloadBuffer[ uxStart ] = ( uint8_t ) uxLength;

            uxStart = uxIndex;
        } while( pucUDPPayloadBuffer[ uxIndex ] != ( uint8_t ) 0U );

        /* Read type and class from the record. */
        pucTail = &( pucUDPPayloadBuffer[ uxStart + 1U ] );

        vSetField16( pucTail, DNSTail_t, usType, ( uint16_t ) uxHostType );
        vSetField16( pucTail, DNSTail_t, usClass, dnsCLASS_IN );

        /* Return the total size of the generated message, which is the space from
         * the last written byte to the beginning of the buffer. */
        return uxIndex + sizeof( DNSTail_t ) + 1U;
    }
/*-----------------------------------------------------------*/

    #if ( ipconfigUSE_DNS_CACHE == 1 ) || ( ipconfigDNS_USE_CALLBACKS == 1 )

/**
 * @brief Read the Name field out of a DNS response packet.
 *
 * @param[in,out] pxSet: a set of variables that are shared among the helper functions.
 * @param[in] uxDestLen: Size of the pcName array.
 *
 * @return If a fully formed name was found, then return the number of bytes processed in pucByte.
 */
        _static size_t prvReadNameField( ParseSet_t * pxSet,
                                         size_t uxDestLen )
        {
            /* 'uxNameLen' counts characters written to 'pxSet->pcName'. */
            size_t uxNameLen = 0U;
            /* The index within .pxSet->pcName'. */
            size_t uxIndex = 0U;
            size_t uxReturnIndex = 0U;
            size_t uxSourceLen = pxSet->uxSourceBytesRemaining;
            size_t uxOffset;
            const uint8_t * pucByte = pxSet->pucByte;

            /* uxCount gets the values from pucByte and counts down to 0.
             * No need to have a different type than that of pucByte */
            size_t uxCount;

            if( uxSourceLen == ( size_t ) 0U )
            {
                /* Return 0 value in case of error. */
                uxIndex = 0U;
            }

            else
            {
                /* 'uxIndex' points to the full name. Walk over the string. */
                while( ( uxIndex < uxSourceLen ) && ( pucByte[ uxIndex ] != ( uint8_t ) 0x00U ) )
                {
                    /* If this is not the first time through the loop, then add a
                     * separator in the output. */
                    if( ( uxNameLen > 0U ) )
                    {
                        if( uxNameLen >= uxDestLen )
                        {
                            uxIndex = 0U;
                            /* coverity[break_stmt] : Break statement terminating the loop */
                            break;
                        }

                        pxSet->pcName[ uxNameLen ] = '.';
                        uxNameLen++;
                    }

                    /* Process the first/next sub-string. */
                    uxCount = ( size_t ) pucByte[ uxIndex ];

                    /* uxIndex should point to the first character now, unless uxCount
                     * is an offset field. */
                    uxIndex++;

                    /* Determine if the name is the fully coded name, or an offset to the name
                     * elsewhere in the message. */
                    if( ( uxCount & dnsNAME_IS_OFFSET ) == dnsNAME_IS_OFFSET )
                    {
                        /* Check if there are enough bytes left. */
                        if( ( uxIndex + 2U ) < uxSourceLen )
                        {
                            /* Only accept a single offset command. */
                            if( uxReturnIndex != 0U )
                            {
                                /* There was a 0xC0 sequence already. */
                                uxIndex = 0U;
                                break;
                            }

                            /* Remember the offset to return. */
                            uxReturnIndex = uxIndex + 1U;
                            /* The offset byte 0xC0 is followed by an offset in the DNS record. */
                            uxOffset = ( size_t ) pucByte[ uxIndex ];

                            if( ( uxOffset + 2U ) > pxSet->uxBufferLength )
                            {
                                uxIndex = 0U;
                                break;
                            }

                            uxSourceLen = pxSet->uxBufferLength - uxOffset;

                            if( ( ( uxOffset + 2U ) < uxSourceLen ) && ( uxOffset >= sizeof( DNSMessage_t ) ) )
                            {
                                /* Process the first/next sub-string. */
                                pucByte = &( pxSet->pucUDPPayloadBuffer[ uxOffset ] );
                                uxCount = ( size_t ) pucByte[ 0 ];
                                uxIndex = 1U;
                            }
                            else
                            {
                                uxIndex = 0U;
                                break;
                            }
                        }
                        else
                        {
                            uxIndex = 0U;
                            break;
                        }
                    }

                    if( ( uxIndex + uxCount ) > uxSourceLen )
                    {
                        uxIndex = 0U;
                        break;
                    }

                    if( ( uxNameLen + uxCount ) >= uxDestLen )
                    {
                        uxIndex = 0U;
                        break;
                    }

                    while( ( uxCount-- != 0U ) && ( uxIndex < uxSourceLen ) )
                    {
                        pxSet->pcName[ uxNameLen ] = ( char ) pucByte[ uxIndex ];
                        uxNameLen++;
                        uxIndex++;
                    }
                } /* while( ( uxIndex < uxSourceLen ) && ( pucByte[ uxIndex ] != ( uint8_t ) 0x00U ) ) */

                /* Confirm that a fully formed name was found. */
                if( uxIndex > 0U )
                {
                    if( ( uxNameLen < uxDestLen ) && ( uxIndex < uxSourceLen ) && ( pucByte[ uxIndex ] == 0U ) )
                    {
                        pxSet->pcName[ uxNameLen ] = 0;
                        uxIndex++;
                    }
                    else
                    {
                        uxIndex = 0U;
                    }
                }
            }

            if( ( uxReturnIndex != 0U ) && ( uxIndex != 0U ) )
            {
                uxIndex = uxReturnIndex;
            }

            return uxIndex;
        }
    #endif /* ipconfigUSE_DNS_CACHE || ipconfigDNS_USE_CALLBACKS */
/*-----------------------------------------------------------*/

    void show_single_addressinfo( const char * pcFormat,
                                  const struct freertos_addrinfo * pxAddress )
    {
        char cBuffer[ 40 ];
        const uint8_t * pucAddress;

        #if ( ipconfigUSE_IPv6 != 0 )
            if( pxAddress->ai_family == FREERTOS_AF_INET6 )
            {
                struct freertos_sockaddr6 * sockaddr6 = ipCAST_PTR_TO_TYPE_PTR( sockaddr6_t, pxAddress->ai_addr );

                pucAddress = ( const uint8_t * ) &( sockaddr6->sin_addrv6 );
            }
            else
        #endif /* ( ipconfigUSE_IPv6 != 0 ) */
        {
            pucAddress = ( const uint8_t * ) &( pxAddress->ai_addr->sin_addr );
        }

        ( void ) FreeRTOS_inet_ntop( pxAddress->ai_family, ( const void * ) pucAddress, cBuffer, sizeof( cBuffer ) );

        if( pcFormat != NULL )
        {
            FreeRTOS_printf( ( pcFormat, cBuffer ) );
        }
        else
        {
            FreeRTOS_printf( ( "Address: %s\n", cBuffer ) );
        }
    }
/*-----------------------------------------------------------*/

/**
 * @brief For testing purposes: print a list of DNS replies.
 *
 * @param[in] pxAddress: The first reply received ( or NULL )
 */
    void show_addressinfo( const struct freertos_addrinfo * pxAddress )
    {
        const struct freertos_addrinfo * ptr = pxAddress;
        BaseType_t xIndex = 0;

        while( ptr != NULL )
        {
            show_single_addressinfo( "Found Address: %s", ptr );

            ptr = ptr->ai_next;
        }

        /* In case the function 'FreeRTOS_printf()` is not implemented. */
        ( void ) xIndex;
    }


/* The function below will only be called :
 * when ipconfigDNS_USE_CALLBACKS == 1
 * when ipconfigUSE_LLMNR == 1
 * for testing purposes, by the module iot_test_freertos_tcp.c
 */
    #if ( ipconfigUSE_DNS == 1 ) && ( ( ipconfigDNS_USE_CALLBACKS == 1 ) || ( ipconfigUSE_LLMNR == 1 ) )

/**
 * @brief Perform some preliminary checks and then parse the DNS packet.
 *
 * @param[in] pxNetworkBuffer: The network buffer to be parsed.
 *
 * @return Always pdFAIL to indicate that the packet was not consumed and must
 *         be released by the caller.
 */
        uint32_t ulDNSHandlePacket( const NetworkBufferDescriptor_t * pxNetworkBuffer )
        {
            size_t uxPayloadSize;
            size_t uxUDPPacketSize = ipSIZE_OF_ETH_HEADER + uxIPHeaderSizePacket( pxNetworkBuffer ) + ipSIZE_OF_UDP_HEADER;

            /* Only proceed if the payload length indicated in the header
             * appears to be valid. */
            if( pxNetworkBuffer->xDataLength >= uxUDPPacketSize )
            {
                uxPayloadSize = pxNetworkBuffer->xDataLength - uxUDPPacketSize;

                if( uxPayloadSize >= sizeof( DNSMessage_t ) )
                {
                    struct freertos_addrinfo * pxAddressInfo = NULL;
                    uint8_t * pucUDPPayload = &( pxNetworkBuffer->pucEthernetBuffer[ uxUDPPacketSize ] );

                    /* The parameter pdFALSE indicates that the reply was not expected. */
                    ( void ) prvParseDNSReply( pucUDPPayload,
                                               uxPayloadSize,
                                               &( pxAddressInfo ),
                                               pdFALSE,
                                               FreeRTOS_ntohs( pxNetworkBuffer->usPort ) );

                    if( pxAddressInfo != NULL )
                    {
                        FreeRTOS_freeaddrinfo( pxAddressInfo );
                    }
                }
            }

            /* The packet was not consumed. */
            return pdFAIL;
        }

    #endif /* ( ipconfigUSE_DNS == 1 ) && ( ( ipconfigDNS_USE_CALLBACKS == 1 ) || ( ipconfigUSE_LLMNR == 1 ) ) */
/*-----------------------------------------------------------*/


    #if ( ipconfigUSE_NBNS == 1 )

/**
 * @brief Handle an NBNS packet.
 *
 * @param[in] pxNetworkBuffer: The network buffer holding the NBNS packet.
 *
 * @return pdFAIL to show that the packet was not consumed.
 */
        uint32_t ulNBNSHandlePacket( NetworkBufferDescriptor_t * pxNetworkBuffer )
        {
            UDPPacket_t * pxUDPPacket = ipCAST_PTR_TO_TYPE_PTR( UDPPacket_t, pxNetworkBuffer->pucEthernetBuffer );
            uint8_t * pucUDPPayloadBuffer = &( pxNetworkBuffer->pucEthernetBuffer[ sizeof( *pxUDPPacket ) ] );

            prvTreatNBNS( pucUDPPayloadBuffer,
                          pxNetworkBuffer->xDataLength,
                          pxUDPPacket->xIPHeader.ulSourceIPAddress );

            /* The packet was not consumed. */
            return pdFAIL;
        }

    #endif /* ipconfigUSE_NBNS */
/*-----------------------------------------------------------*/

    #if ( ( ipconfigUSE_NBNS == 1 ) || ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )

/**
 * @brief Find the best matching end-point given a reply that was received.
 *
 * @param[in] pxNetworkBuffer: The Ethernet packet that was received.
 *
 * @return An end-point.
 */
        static NetworkEndPoint_t * prvFindEndPointOnNetMask( NetworkBufferDescriptor_t * pxNetworkBuffer )
        {
            NetworkEndPoint_t * pxEndPoint;

            #if ( ipconfigUSE_IPv6 != 0 )
                IPPacket_IPv6_t * xIPPacket_IPv6 = ipCAST_PTR_TO_TYPE_PTR( IPPacket_IPv6_t, pxNetworkBuffer->pucEthernetBuffer );

                if( xIPPacket_IPv6->xEthernetHeader.usFrameType == ipIPv6_FRAME_TYPE )
                {
                    pxEndPoint = FreeRTOS_FindEndPointOnNetMask_IPv6( &xIPPacket_IPv6->xIPHeader.xSourceAddress );
                }
                else
            #endif /* ( ipconfigUSE_IPv6 != 0 ) */
            {
                IPPacket_t * xIPPacket = ipCAST_PTR_TO_TYPE_PTR( IPPacket_t, pxNetworkBuffer->pucEthernetBuffer );

                pxEndPoint = FreeRTOS_FindEndPointOnNetMask( xIPPacket->xIPHeader.ulSourceIPAddress, 6 );
            }

            if( pxEndPoint != NULL )
            {
                pxNetworkBuffer->pxEndPoint = pxEndPoint;
            }

            return pxEndPoint;
        }
    #endif /* ( ( ipconfigUSE_NBNS == 1 ) || ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) ) */
/*-----------------------------------------------------------*/

/**
 * @brief Parse the array of questions that are received from a DNS server.
 * @param[in,out] pxSet: a set of variables that are shared among the helper functions.
 * @return pdTRUE when parsing was successful, otherwise pdFALSE.
 */
    static BaseType_t prvParseDNS_ReadQuestions( ParseSet_t * pxSet )
    {
        size_t x;
        size_t uxResult;
        BaseType_t xReturn = pdTRUE;

        for( x = 0U; x < pxSet->usQuestions; x++ )
        {
            #if ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )
                {
                    if( x == 0U )
                    {
                        pxSet->pcRequestedName = ( char * ) pxSet->pucByte;
                    }
                }
            #endif /* ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) ) */

            {
                uxResult = prvReadNameField( pxSet,
                                             sizeof( pxSet->pcName ) );

                /* Check for a malformed response. */
                if( uxResult == 0U )
                {
                    xReturn = pdFALSE;
                    break;
                }

                pxSet->pucByte = &( pxSet->pucByte[ uxResult ] );
                pxSet->uxSourceBytesRemaining -= uxResult;
            }

            /* Check the remaining buffer size. */
            if( pxSet->uxSourceBytesRemaining >= sizeof( uint32_t ) )
            {
                #if ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )
                    {
                        /* usChar2u16 returns value in host endianness. */
                        pxSet->usType = usChar2u16( pxSet->pucByte );
                        pxSet->usClass = usChar2u16( &( pxSet->pucByte[ 2 ] ) );
                    }
                #endif /* ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) ) */

                /* Skip the type and class fields. */
                pxSet->pucByte = &( pxSet->pucByte[ sizeof( uint32_t ) ] );
                pxSet->uxSourceBytesRemaining -= sizeof( uint32_t );
            }
            else
            {
                xReturn = pdFALSE;
                break;
            }
        }     /* for( x = 0U; x < pxSet->usQuestions; x++ ) */

        return xReturn;
    }
/*-----------------------------------------------------------*/

    #if ( ipconfigUSE_DNS_CACHE == 1 )

/**
 * @brief Store an IP-address in the DNS cache, and issue some logging.
 * @param[in] pxSet: a set of variables that are shared among the helper functions.
 * @param[out] pxIP_Address: The address found will be copied to 'pxIP_Address'.
 * @param[in] ulTTL: The Time To Live value, used for cleaning the cache.
 */
        static void prvParseDNS_StoreToCache( ParseSet_t * pxSet,
                                              IPv46_Address_t * pxIP_Address,
                                              uint32_t ulTTL )
        {
            /* The reply will only be stored in the DNS cache when the
             * request was issued by this device. */
            if( pxSet->xDoStore != pdFALSE )
            {
                ( void ) prvProcessDNSCache( pxSet->pcName, pxIP_Address, ulTTL, pdFALSE, NULL );
                pxSet->usNumARecordsStored++;     /* Track # of A records stored */
            }

            #if ( ipconfigUSE_IPv6 != 0 )
                if( pxSet->usType == ( uint16_t ) dnsTYPE_AAAA_HOST )
                {
                    char cBuffer[ 40 ];

                    ( void ) FreeRTOS_inet_ntop( FREERTOS_AF_INET6, ( const void * ) pxIP_Address->xAddress_IPv6.ucBytes, cBuffer, sizeof( cBuffer ) );
                    FreeRTOS_printf( ( "DNS[0x%04X]: The answer to '%s' (%s) will%s been stored\n",
                                       ( unsigned ) pxSet->pxDNSMessageHeader->usIdentifier,
                                       pxSet->pcName,
                                       cBuffer,
                                       ( pxSet->xDoStore != 0 ) ? "" : " NOT" ) );
                }
                else
            #endif /* ( ipconfigUSE_IPv6 != 0 ) */
            {
                char cBuffer[ 16 ];

                ( void ) FreeRTOS_inet_ntop( FREERTOS_AF_INET, ( const void * ) &( pxSet->ulIPAddress ), cBuffer, sizeof( cBuffer ) );
                /* Show what has happened. */
                FreeRTOS_printf( ( "DNS[0x%04X]: The answer to '%s' (%s) will%s be stored\n",
                                   pxSet->pxDNSMessageHeader->usIdentifier,
                                   pxSet->pcName,
                                   cBuffer,
                                   ( pxSet->xDoStore != 0 ) ? "" : " NOT" ) );
            }
        }
    #endif /* ( ipconfigUSE_DNS_CACHE == 1 ) */

/**
 * @brief Copy an IP-address to a variable, and add it to a linked list of IP-addresses.
 * @param[in] pxSet: a set of variables that are shared among the helper functions.
 * @param[out] pxIP_Address: The address found will be copied to 'pxIP_Address'.
 * @param[out] ppxAddressInfo: The address found will also be stored in this linked list.
 */
    static void prvParseDNS_StoreAnswer( ParseSet_t * pxSet,
                                         IPv46_Address_t * pxIP_Address,
                                         struct freertos_addrinfo ** ppxAddressInfo )
    {
        struct freertos_addrinfo * pxNewAddress = NULL;

        /* Copy the IP address out of the record. */
        #if ( ipconfigUSE_IPv6 != 0 )
            if( pxSet->usType == ( uint16_t ) dnsTYPE_AAAA_HOST )
            {
                ( void ) memcpy( pxIP_Address->xAddress_IPv6.ucBytes,
                                 &( pxSet->pucByte[ sizeof( DNSAnswerRecord_t ) ] ),
                                 ipSIZE_OF_IPv6_ADDRESS );

                if( ppxAddressInfo != NULL )
                {
                    pxNewAddress = pxNew_AddrInfo( pxSet->pcName, FREERTOS_AF_INET6, pxIP_Address->xAddress_IPv6.ucBytes );
                }

                pxIP_Address->xIs_IPv6 = pdTRUE;

                /* Return non-zero to inform the caller that a valid
                 * IPv6 address was found. */
                pxSet->ulIPAddress = 1U;
            }
            else
        #endif /* ( ipconfigUSE_IPv6 != 0 ) */
        {
            void * pvCopyDest;
            const void * pvCopySource;

            /* Copy the IP address out of the record. Using different pointers
             * to copy only the portion we want is intentional here. */
            pvCopyDest = &( pxSet->ulIPAddress );
            pvCopySource = &( pxSet->pucByte[ sizeof( DNSAnswerRecord_t ) ] );
            ( void ) memcpy( pvCopyDest,
                             pvCopySource,
                             ipSIZE_OF_IPv4_ADDRESS );

            if( ppxAddressInfo != NULL )
            {
                uint8_t * ucBytes = ( uint8_t * ) &( pxSet->ulIPAddress );

                pxNewAddress = pxNew_AddrInfo( pxSet->pcName, FREERTOS_AF_INET4, ucBytes );
            }

            pxIP_Address->ulIPAddress = pxSet->ulIPAddress;
            #if ( ipconfigUSE_IPv6 != 0 )
                pxIP_Address->xIs_IPv6 = pdFALSE;
            #endif /* ( ipconfigUSE_IPv6 != 0 ) */
        }

        if( pxNewAddress != NULL )
        {
            if( *( ppxAddressInfo ) == NULL )
            {
                /* For the first address found. */
                *( ppxAddressInfo ) = pxNewAddress;
            }
            else
            {
                /* For the next address found. */
                *( pxSet->ppxLastAddress ) = pxNewAddress;
            }

            pxSet->ppxLastAddress = &( pxNewAddress->ai_next );
        }
    }

/**
 * @brief Parse the array of answers that are received from a DNS server.
 * @param[in] pxSet: a set of variables that are shared among the helper functions.
 * @param[out] ppxAddressInfo: a linked list storing the DNS answers.
 * @return pdTRUE when successful, otherwise pdFALSE.
 */
    static BaseType_t prvParseDNS_ReadAnswers( ParseSet_t * pxSet,
                                               struct freertos_addrinfo ** ppxAddressInfo )
    {
        const uint16_t usCount = ( uint16_t ) ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY;
        size_t x;
        size_t uxResult;
        BaseType_t xReturn = pdTRUE;
        const DNSAnswerRecord_t * pxDNSAnswerRecord;
        IPv46_Address_t xIP_Address;

        for( x = 0U; x < pxSet->pxDNSMessageHeader->usAnswers; x++ )
        {
            BaseType_t xDoAccept = pdFALSE;

            if( pxSet->usNumARecordsStored >= usCount )
            {
                /* Only count ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY number of records. */
                break;
            }

            uxResult = prvReadNameField( pxSet,
                                         sizeof( pxSet->pcName ) );

            /* Check for a malformed response. */
            if( uxResult == 0U )
            {
                xReturn = pdFALSE;
                break;
            }

            pxSet->pucByte = &( pxSet->pucByte[ uxResult ] );
            pxSet->uxSourceBytesRemaining -= uxResult;

            /* Is there enough data for an IPv4 A record answer and, if so,
             * is this an A record? */
            if( pxSet->uxSourceBytesRemaining < sizeof( uint16_t ) )
            {
                xReturn = pdFALSE;
                break;
            }

            pxSet->usType = usChar2u16( pxSet->pucByte );

            #if ( ipconfigUSE_IPv6 != 0 )
                if( pxSet->usType == ( uint16_t ) dnsTYPE_AAAA_HOST )
                {
                    pxSet->uxAddressLength = ipSIZE_OF_IPv6_ADDRESS;

                    if( pxSet->uxSourceBytesRemaining >= ( sizeof( DNSAnswerRecord_t ) + pxSet->uxAddressLength ) )
                    {
                        xDoAccept = pdTRUE;
                    }
                }
                else
            #endif /* #if( ipconfigUSE_IPv6 != 0 ) */

            if( pxSet->usType == ( uint16_t ) dnsTYPE_A_HOST )
            {
                /* uxAddressLength is already ipSIZE_OF_IPv4_ADDRESS. */
                if( pxSet->uxSourceBytesRemaining >= ( sizeof( DNSAnswerRecord_t ) + pxSet->uxAddressLength ) )
                {
                    xDoAccept = pdTRUE;
                }
            }
            else
            {
                /* A unknown type is received that is not handled. xDoAccept is pdFALSE. */
            }

            if( xDoAccept == pdTRUE )
            {
                /* This is the required record type and is of sufficient size. */

                /* Mapping pucByte to a DNSAnswerRecord allows easy access of the
                 * fields of the structure. */
                pxDNSAnswerRecord = ipCAST_PTR_TO_TYPE_PTR( DNSAnswerRecord_t, pxSet->pucByte );

                /* Sanity check the data length of an IPv4 answer. */
                if( FreeRTOS_ntohs( pxDNSAnswerRecord->usDataLength ) == ( uint16_t ) pxSet->uxAddressLength )
                {
                    prvParseDNS_StoreAnswer( pxSet, &( xIP_Address ), ppxAddressInfo );

                    #if ( ipconfigDNS_USE_CALLBACKS == 1 )
                        {
                            BaseType_t xCallbackResult;

                            #if ( ipconfigUSE_IPv6 != 0 )
                                {
                                    xCallbackResult = xDNSDoCallback( pxSet, ( ppxAddressInfo != NULL ) ? *( ppxAddressInfo ) : NULL );
                                }
                            #else
                                {
                                    xCallbackResult = xDNSDoCallback( pxSet, pxSet->ulIPAddress );
                                }
                            #endif /* ( ipconfigUSE_IPv6 != 0 ) */

                            /* See if any asynchronous call was made to FreeRTOS_gethostbyname_a() */
                            if( xCallbackResult != pdFALSE )
                            {
                                /* This device has requested this DNS look-up.
                                 * The result may be stored in the DNS cache. */
                                pxSet->xDoStore = pdTRUE;
                            }
                        }
                    #endif /* ipconfigDNS_USE_CALLBACKS == 1 */
                    #if ( ipconfigUSE_DNS_CACHE == 1 )
                        {
                            prvParseDNS_StoreToCache( pxSet, &( xIP_Address ), pxDNSAnswerRecord->ulTTL );
                        }
                    #endif /* ipconfigUSE_DNS_CACHE */
                }
                else
                {
                    FreeRTOS_printf( ( "DNS sanity check failed: %u != %u\n",
                                       FreeRTOS_ntohs( pxDNSAnswerRecord->usDataLength ),
                                       ( unsigned ) pxSet->uxAddressLength ) );
                }

                pxSet->pucByte = &( pxSet->pucByte[ sizeof( DNSAnswerRecord_t ) + pxSet->uxAddressLength ] );
                pxSet->uxSourceBytesRemaining -= ( sizeof( DNSAnswerRecord_t ) + pxSet->uxAddressLength );
            }
            else if( pxSet->uxSourceBytesRemaining >= sizeof( DNSAnswerRecord_t ) )
            {
                uint16_t usDataLength;

                /* It's not an A record, so skip it. Get the header location
                 * and then jump over the header. */
                /* Cast the response to DNSAnswerRecord for easy access to fields of the DNS response. */
                pxDNSAnswerRecord = ipCAST_PTR_TO_TYPE_PTR( DNSAnswerRecord_t, pxSet->pucByte );

                pxSet->pucByte = &( pxSet->pucByte[ sizeof( DNSAnswerRecord_t ) ] );
                pxSet->uxSourceBytesRemaining -= sizeof( DNSAnswerRecord_t );

                /* Determine the length of the answer data from the header. */
                usDataLength = FreeRTOS_ntohs( pxDNSAnswerRecord->usDataLength );

                /* Jump over the answer. */
                if( pxSet->uxSourceBytesRemaining >= usDataLength )
                {
                    pxSet->pucByte = &( pxSet->pucByte[ usDataLength ] );
                    pxSet->uxSourceBytesRemaining -= usDataLength;
                }
                else
                {
                    /* Malformed response. */
                    xReturn = pdFALSE;
                    break;
                }
            }
            else
            {
                /* Do nothing */
            }
        }

        return xReturn;
    }
/*-----------------------------------------------------------*/

    #if ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )

/** @brief An LLMNR lookup of a host was received. The application code is consulted
 *        by calling xApplicationDNSQueryHook(), which returns true in case the
 *        driver should reply to the lookup.
 * @param[in] pxSet: a set of variables that are shared among the helper functions.
 * @param[in] pucUDPPayloadBuffer: a pointer to the first byte of the LLMNR
 *            lookup message.
 */
        static void prvParseDNS_HandleLLMNRRequest( ParseSet_t * pxSet,
                                                    uint8_t * pucUDPPayloadBuffer )
        {
            /* If this is not a reply to our DNS request, it might an LLMNR
             * request. */
            NetworkBufferDescriptor_t * pxNetworkBuffer;
            NetworkEndPoint_t * pxEndPoint, xEndPoint;
            int16_t usLength;
            LLMNRAnswer_t * pxAnswer;
            size_t uxDataLength;
            size_t uxExtraLength;
            size_t uxOffsets[ 3 ];
            uint8_t * pucNewBuffer = NULL;

            do
            {
                #if ( ipconfigUSE_IPv6 == 0 )
                    if( pxSet->usType != dnsTYPE_A_HOST )
                    {
                        /* Only allow IPv4 format, because ipconfigUSE_IPv6 is not defined. */
                        break;
                    }
                #endif /* ipconfigUSE_IPv6 */

                pxNetworkBuffer = pxUDPPayloadBuffer_to_NetworkBuffer( pucUDPPayloadBuffer );

                /* This test could be replaced with a assert(). */
                if( pxNetworkBuffer == NULL )
                {
                    break;
                }

                if( pxNetworkBuffer->pxEndPoint == NULL )
                {
                    /* NetworkInterface is obliged to set 'pxEndPoint' in every received packet,
                     * but in case this has not be done, set it here. */

                    pxNetworkBuffer->pxEndPoint = prvFindEndPointOnNetMask( pxNetworkBuffer );
                    FreeRTOS_printf( ( "prvParseDNS_HandleLLMNRRequest: No pxEndPoint yet? Using %lxip\n",
                                       FreeRTOS_ntohl( pxNetworkBuffer->pxEndPoint ? pxNetworkBuffer->pxEndPoint->ipv4_settings.ulIPAddress : 0U ) ) );

                    if( pxNetworkBuffer->pxEndPoint == NULL )
                    {
                        break;
                    }
                }

                pxEndPoint = pxNetworkBuffer->pxEndPoint;

                /* Make a copy of the end-point because xApplicationDNSQueryHook() is allowed
                 * to write into it. */
                ( void ) memcpy( &( xEndPoint ), pxEndPoint, sizeof( xEndPoint ) );
                #if ( ipconfigUSE_IPv6 != 0 )
                    {
                        /*logging*/
                        FreeRTOS_printf( ( "prvParseDNS_HandleLLMNRRequest[%s]: type %04X\n", pxSet->pcName, pxSet->usType ) );

                        xEndPoint.usDNSType = pxSet->usType;
                    }
                #endif /* ( ipconfigUSE_IPv6 != 0 ) */

                if( xApplicationDNSQueryHook( &xEndPoint, pxSet->pcName ) == pdFALSE )
                {
                    /* This device doesn't have this name. */
                    break;
                }

                /* The IP-header size depends on what was received in 'pxNetworkBuffer'. */
                uxDataLength = ipSIZE_OF_ETH_HEADER + uxIPHeaderSizePacket( pxNetworkBuffer ) + sizeof( UDPHeader_t ) + pxNetworkBuffer->xDataLength;

                #if ( ipconfigUSE_IPv6 != 0 )
                    if( pxSet->usType == dnsTYPE_AAAA_HOST )
                    {
                        uxExtraLength = sizeof( LLMNRAnswer_t ) + ipSIZE_OF_IPv6_ADDRESS - sizeof( pxAnswer->ulIPAddress );
                    }
                    else
                #endif /* ( ipconfigUSE_IPv6 != 0 ) */
                {
                    uxExtraLength = sizeof( LLMNRAnswer_t );
                }

                /* The field xDataLength was set to the length of the UDP
                 * payload.  The answer (reply) will be longer than the
                 * request, so the packet must be resized. */
                uxOffsets[ 0 ] = ( size_t ) ( pucUDPPayloadBuffer - pxNetworkBuffer->pucEthernetBuffer );
                uxOffsets[ 1 ] = ( size_t ) ( pxSet->pcRequestedName - ( ( char * ) pxNetworkBuffer->pucEthernetBuffer ) );
                uxOffsets[ 2 ] = ( size_t ) ( pxSet->pucByte - pxNetworkBuffer->pucEthernetBuffer );

                /* Restore the 'xDataLength' field. */
                pxNetworkBuffer->xDataLength = uxDataLength;
                pxNetworkBuffer = pxResizeNetworkBufferWithDescriptor( pxNetworkBuffer, uxDataLength + uxExtraLength );

                if( pxNetworkBuffer == NULL )
                {
                    break;
                }

                pucNewBuffer = &( pxNetworkBuffer->pucEthernetBuffer[ ( BaseType_t ) uxOffsets[ 0 ] ] );
                pxSet->pcRequestedName = ( char * ) &( pxNetworkBuffer->pucEthernetBuffer[ uxOffsets[ 1 ] ] );
                pxSet->pucByte = &( pxNetworkBuffer->pucEthernetBuffer[ uxOffsets[ 2 ] ] );

                pxAnswer = ipCAST_PTR_TO_TYPE_PTR( LLMNRAnswer_t, pxSet->pucByte );

                /* Leave 'usIdentifier' and 'usQuestions' untouched. */

                vSetField16( pucNewBuffer, DNSMessage_t, usFlags, dnsLLMNR_FLAGS_IS_REPONSE );         /* Set the response flag */
                vSetField16( pucNewBuffer, DNSMessage_t, usAnswers, 1 );                               /* Provide a single answer */
                vSetField16( pucNewBuffer, DNSMessage_t, usAuthorityRRs, 0 );                          /* No authority */
                vSetField16( pucNewBuffer, DNSMessage_t, usAdditionalRRs, 0 );                         /* No additional info */

                pxAnswer->ucNameCode = dnsNAME_IS_OFFSET;
                pxAnswer->ucNameOffset = ( uint8_t ) ( pxSet->pcRequestedName - ( char * ) pucNewBuffer );

                vSetField16( pxSet->pucByte, LLMNRAnswer_t, usType, pxSet->usType );     /* Type A: host */
                vSetField16( pxSet->pucByte, LLMNRAnswer_t, usClass, dnsCLASS_IN );      /* 1: Class IN */
                vSetField32( pxSet->pucByte, LLMNRAnswer_t, ulTTL, dnsLLMNR_TTL_VALUE );

                #if ( ipconfigUSE_IPv6 != 0 )
                    if( pxSet->usType == dnsTYPE_AAAA_HOST )
                    {
                        size_t uxDistance;
                        NetworkEndPoint_t * pxReplyEndpoint = FreeRTOS_FirstEndPoint_IPv6( NULL );

                        if( pxReplyEndpoint == NULL )
                        {
                            break;
                        }

                        vSetField16( pxSet->pucByte, LLMNRAnswer_t, usDataLength, ipSIZE_OF_IPv6_ADDRESS );
                        ( void ) memcpy( &( pxAnswer->ulIPAddress ), pxReplyEndpoint->ipv6_settings.xIPAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
                        uxDistance = ( size_t ) ( pxSet->pucByte - pucNewBuffer );
                        usLength = ipNUMERIC_CAST( int16_t, sizeof( *pxAnswer ) + uxDistance + ipSIZE_OF_IPv6_ADDRESS - sizeof( pxAnswer->ulIPAddress ) );
                    }
                    else
                #endif /* ( ipconfigUSE_IPv6 != 0 ) */
                {
                    /*logging*/
                    FreeRTOS_printf( ( "LLMNR return IPv4 %lxip\n", FreeRTOS_ntohl( xEndPoint.ipv4_settings.ulIPAddress ) ) );
                    vSetField16( pxSet->pucByte, LLMNRAnswer_t, usDataLength, ( uint16_t ) sizeof( pxAnswer->ulIPAddress ) );
                    vSetField32( pxSet->pucByte, LLMNRAnswer_t, ulIPAddress, FreeRTOS_ntohl( xEndPoint.ipv4_settings.ulIPAddress ) );

                    usLength = ( int16_t ) ( sizeof( *pxAnswer ) + ( size_t ) ( pxSet->pucByte - pucNewBuffer ) );
                }

                #if ( ipconfigUSE_IPv6 == 0 )
                    if( pxSet->usType == dnsTYPE_A_HOST )
                #else
                    if( ( pxSet->usType == dnsTYPE_A_HOST ) || ( pxSet->usType == dnsTYPE_AAAA_HOST ) )
                #endif /* ipconfigUSE_IPv6 */
                {
                    prvReplyDNSMessage( pxNetworkBuffer, usLength );
                }
            } while( ipFALSE_BOOL );
        }
    #endif /* ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) ) */
/*-----------------------------------------------------------*/

/**
 * @brief Process a response packet from a DNS server, or an mDNS or LLMNR reply.
 *
 * @param[in] pucUDPPayloadBuffer: The DNS response received as a UDP
 *                                 payload.
 * @param[in] uxBufferLength: Length of the UDP payload buffer.
 * @param[in] ppxAddressInfo: A pointer to a pointer where the results will be stored.
 * @param[in] xExpected: indicates whether the identifier in the reply
 *                       was expected, and thus if the DNS cache may be
 *                       updated with the reply.
 * @param[in] usPort: The server port number in order to identify the protocol.
 *
 * @return The IP address in the DNS response if present and if xExpected is set to pdTRUE.
 *         An error code (dnsPARSE_ERROR) if there was an error in the DNS response.
 *         0 if xExpected set to pdFALSE.
 */
    static uint32_t prvParseDNSReply( uint8_t * pucUDPPayloadBuffer,
                                      size_t uxBufferLength,
                                      struct freertos_addrinfo ** ppxAddressInfo,
                                      BaseType_t xExpected,
                                      uint16_t usPort )
    {
        ParseSet_t xSet;

        BaseType_t xReturn = pdTRUE;

        ( void ) memset( &( xSet ), 0, sizeof( xSet ) );
        xSet.usPortNumber = usPort;
        xSet.ppxLastAddress = &( xSet.pxLastAddress );

        xSet.uxAddressLength = ipSIZE_OF_IPv4_ADDRESS;

        #if ( ipconfigUSE_DNS_CACHE == 1 ) || ( ipconfigDNS_USE_CALLBACKS == 1 )
            xSet.xDoStore = xExpected;
        #endif

        /* Ensure that the buffer is of at least minimal DNS message length. */
        if( uxBufferLength < sizeof( DNSMessage_t ) )
        {
            xReturn = pdFALSE;
        }
        else
        {
            xSet.uxBufferLength = uxBufferLength;
            xSet.uxSourceBytesRemaining = uxBufferLength;

            /* Parse the DNS message header. Map the byte stream onto a structure
             * for easier access. */
            xSet.pxDNSMessageHeader = ipCAST_PTR_TO_TYPE_PTR( DNSMessage_t, pucUDPPayloadBuffer );

            /* Introduce a do {} while (0) to allow the use of breaks. */
            do
            {
                /* Start at the first byte after the header. */
                xSet.pucUDPPayloadBuffer = pucUDPPayloadBuffer;
                xSet.pucByte = &( pucUDPPayloadBuffer[ sizeof( DNSMessage_t ) ] );
                xSet.uxSourceBytesRemaining -= sizeof( DNSMessage_t );

                /* Skip any question records. */
                xSet.usQuestions = FreeRTOS_ntohs( xSet.pxDNSMessageHeader->usQuestions );

                xReturn = prvParseDNS_ReadQuestions( &( xSet ) );

                if( xReturn == pdFALSE )
                {
                    /* No need to proceed. Break out of the do-while loop. */
                    break;
                }

                #if ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )
                    #if ( ipconfigUSE_IPv6 != 0 )
                        if( ( xSet.usQuestions != 0U ) &&
                            ( xSet.usType != ( uint16_t ) dnsTYPE_A_HOST ) &&
                            ( xSet.usType != ( uint16_t ) dnsTYPE_AAAA_HOST ) )
                        {
                            break;
                        }
                    #else
                        if( ( xSet.usQuestions != 0U ) &&
                            ( xSet.usType != ( uint16_t ) dnsTYPE_A_HOST ) )
                        {
                            break;
                        }
                    #endif /* if ( ipconfigUSE_IPv6 != 0 ) */
                #endif /* if ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) ) */

                /* Search through the answer records. */
                xSet.pxDNSMessageHeader->usAnswers = FreeRTOS_ntohs( xSet.pxDNSMessageHeader->usAnswers );

                if( ( xSet.pxDNSMessageHeader->usFlags & dnsRX_FLAGS_MASK ) == dnsEXPECTED_RX_FLAGS )
                {
                    xReturn = prvParseDNS_ReadAnswers( &( xSet ), ppxAddressInfo );
                }

                #if ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )
                    else if( ( xSet.usQuestions != ( uint16_t ) 0U ) &&
                             ( xSet.usClass == dnsCLASS_IN ) &&
                             ( xSet.pcRequestedName != NULL ) )
                    {
                        prvParseDNS_HandleLLMNRRequest( &( xSet ), pucUDPPayloadBuffer );
                    }
                    else
                    {
                        /* Not an expected reply. */
                    }
                #endif /* ( ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) ) */
            } while( ipFALSE_BOOL );
        }

        if( xReturn == pdFALSE )
        {
            /* There was an error while parsing the DNS response. Return error code. */
            xSet.ulIPAddress = dnsPARSE_ERROR;
        }
        else if( xExpected == pdFALSE )
        {
            /* Do not return a valid IP-address in case the reply was not expected. */
            xSet.ulIPAddress = 0U;
        }
        else
        {
            /* The IP-address was found in prvParseDNS_ReadAnswers(), and it will be returned. */
        }

        return xSet.ulIPAddress;
    }
/*-----------------------------------------------------------*/

    #if ( ipconfigUSE_NBNS == 1 )

/**
 * @brief Respond to an NBNS query or an NBNS reply.
 *
 * @param[in] pucPayload: the UDP payload of the NBNS message.
 * @param[in] uxBufferLength: Length of the Buffer.
 * @param[in] ulIPAddress: IP address of the sender.
 */
        static void prvTreatNBNS( uint8_t * pucPayload,
                                  size_t uxBufferLength,
                                  uint32_t ulIPAddress )
        {
            uint16_t usFlags, usType, usClass;
            uint8_t * pucSource, * pucTarget;
            uint8_t ucByte;
            uint8_t ucNBNSName[ 17 ];
            uint8_t * pucUDPPayloadBuffer = pucPayload;
            NetworkBufferDescriptor_t * pxNetworkBuffer;
            size_t uxBytesNeeded = sizeof( UDPPacket_t ) + sizeof( NBNSRequest_t );

            do
            {
                NetworkEndPoint_t xEndPoint;
                BaseType_t xMustReply = pdFALSE;

                /* Check for minimum buffer size. */
                if( uxBufferLength < uxBytesNeeded )
                {
                    break;
                }

                /* Read the request flags in host endianness. */
                usFlags = usChar2u16( &( pucUDPPayloadBuffer[ offsetof( NBNSRequest_t, usFlags ) ] ) );

                if( ( usFlags & dnsNBNS_FLAGS_OPCODE_MASK ) != dnsNBNS_FLAGS_OPCODE_QUERY )
                {
                    break;
                }

                usType = usChar2u16( &( pucUDPPayloadBuffer[ offsetof( NBNSRequest_t, usType ) ] ) );
                usClass = usChar2u16( &( pucUDPPayloadBuffer[ offsetof( NBNSRequest_t, usClass ) ] ) );

                /* Not used for now */
                ( void ) usClass;

                /* For NBNS a name is 16 bytes long, written with capitals only.
                 * Make sure that the copy is terminated with a zero. */
                pucTarget = &( ucNBNSName[ sizeof( ucNBNSName ) - 2U ] );
                pucTarget[ 1 ] = ( uint8_t ) 0U;

                /* Start with decoding the last 2 bytes. */
                pucSource = &( pucUDPPayloadBuffer[ ( dnsNBNS_ENCODED_NAME_LENGTH - 2 ) + offsetof( NBNSRequest_t, ucName ) ] );

                for( ; ; )
                {
                    const uint8_t ucCharA = ( uint8_t ) 0x41U;

                    ucByte = ( ( uint8_t ) ( ( pucSource[ 0 ] - ucCharA ) << 4 ) ) | ( pucSource[ 1 ] - ucCharA );

                    /* Make sure there are no trailing spaces in the name. */
                    if( ( ucByte == ( uint8_t ) ' ' ) && ( pucTarget[ 1 ] == 0U ) )
                    {
                        ucByte = 0U;
                    }

                    *pucTarget = ucByte;

                    if( pucTarget == ucNBNSName )
                    {
                        break;
                    }

                    pucTarget -= 1;
                    pucSource -= 2;
                }

                #if ( ipconfigUSE_DNS_CACHE == 1 )
                    {
                        if( ( usFlags & dnsNBNS_FLAGS_RESPONSE ) != 0U )
                        {
                            /* If this is a response from another device,
                             * add the name to the DNS cache */
                            IPv46_Address_t xIPAddress;

                            xIPAddress.ulIPAddress = ulIPAddress;
                            #if ( ipconfigUSE_IPv6 != 0 )
                                {
                                    xIPAddress.xIs_IPv6 = pdFALSE;
                                }
                            #endif

                            ( void ) prvProcessDNSCache( ( char * ) ucNBNSName, &( xIPAddress ), 0, pdFALSE, NULL );
                        }
                    }
                #else /* if ( ipconfigUSE_DNS_CACHE == 1 ) */
                    {
                        /* Avoid compiler warnings. */
                        ( void ) ulIPAddress;
                    }
                #endif /* ipconfigUSE_DNS_CACHE */

                pxNetworkBuffer = pxUDPPayloadBuffer_to_NetworkBuffer( pucUDPPayloadBuffer );

                /* When pxUDPPayloadBuffer_to_NetworkBuffer fails, there
                 * is a real problem, like data corruption. */
                configASSERT( pxNetworkBuffer != NULL );

                if( pxNetworkBuffer->pxEndPoint == NULL )
                {
                    pxNetworkBuffer->pxEndPoint = prvFindEndPointOnNetMask( pxNetworkBuffer );
                }

                if( pxNetworkBuffer->pxEndPoint != NULL )
                {
                    ( void ) memcpy( &xEndPoint, pxNetworkBuffer->pxEndPoint, sizeof( xEndPoint ) );
                }

                #if ( ipconfigUSE_IPv6 != 0 )
                    {
                        xEndPoint.bits.bIPv6 = pdFALSE_UNSIGNED;
                    }
                #endif

                /* If this packet is not a response, and if it is an NBNS request. */
                if( ( ( usFlags & dnsNBNS_FLAGS_RESPONSE ) == 0U ) &&
                    ( usType == dnsNBNS_TYPE_NET_BIOS ) )
                {
                    if( xApplicationDNSQueryHook( &( xEndPoint ), ( const char * ) ucNBNSName ) != pdFALSE )
                    {
                        xMustReply = pdTRUE;
                    }
                }

                if( xMustReply == pdFALSE )
                {
                    break;
                }

                uint16_t usLength;
                NetworkBufferDescriptor_t * pxNewBuffer = NULL;

                /* Someone is looking for a device with ucNBNSName,
                 * prepare a positive reply. */

                if( xBufferAllocFixedSize == pdFALSE )
                {
                    /* The field xDataLength was set to the total length of the UDP packet,
                     * i.e. the payload size plus sizeof( UDPPacket_t ). */
                    pxNewBuffer = pxDuplicateNetworkBufferWithDescriptor( pxNetworkBuffer, pxNetworkBuffer->xDataLength + sizeof( NBNSAnswer_t ) );

                    if( pxNewBuffer == NULL )
                    {
                        break;
                    }

                    pxNetworkBuffer = pxNewBuffer;
                }

                /* Should not occur: pucUDPPayloadBuffer is part of a xNetworkBufferDescriptor */

                /* As the fields in the structures are not word-aligned, we have to
                 * copy the values byte-by-byte using macro's vSetField16() and vSetField32() */
                vSetField16( pucUDPPayloadBuffer, DNSMessage_t, usFlags, dnsNBNS_QUERY_RESPONSE_FLAGS );         /* 0x8500 */
                vSetField16( pucUDPPayloadBuffer, DNSMessage_t, usQuestions, 0 );
                vSetField16( pucUDPPayloadBuffer, DNSMessage_t, usAnswers, 1 );
                vSetField16( pucUDPPayloadBuffer, DNSMessage_t, usAuthorityRRs, 0 );
                vSetField16( pucUDPPayloadBuffer, DNSMessage_t, usAdditionalRRs, 0 );

                uint8_t * pucByte = &( pucUDPPayloadBuffer[ offsetof( NBNSRequest_t, usType ) ] );

                vSetField16( pucByte, NBNSAnswer_t, usType, usType );                    /* Type */
                vSetField16( pucByte, NBNSAnswer_t, usClass, dnsNBNS_CLASS_IN );         /* Class */
                vSetField32( pucByte, NBNSAnswer_t, ulTTL, dnsNBNS_TTL_VALUE );
                vSetField16( pucByte, NBNSAnswer_t, usDataLength, 6 );                   /* 6 bytes including the length field */
                vSetField16( pucByte, NBNSAnswer_t, usNbFlags, dnsNBNS_NAME_FLAGS );
                vSetField32( pucByte, NBNSAnswer_t, ulIPAddress, FreeRTOS_ntohl( xEndPoint.ipv4_settings.ulIPAddress ) );

                usLength = ( uint16_t ) ( sizeof( NBNSAnswer_t ) + ( size_t ) offsetof( NBNSRequest_t, usType ) );

                prvReplyDNSMessage( pxNetworkBuffer, ( BaseType_t ) usLength );

                if( pxNewBuffer != NULL )
                {
                    vReleaseNetworkBufferAndDescriptor( pxNewBuffer );
                }
            }  while( ipFALSE_BOOL );
        }

    #endif /* ipconfigUSE_NBNS */
/*-----------------------------------------------------------*/

/**
 * @brief Bind the socket to a port number.
 * @param[in] xSocket: the socket that must be bound.
 * @param[in] usPort: the port number to bind to.
 * @return The created socket - or NULL if the socket could not be created or could not be bound.
 */
    static BaseType_t prvBindDNSSocket( Socket_t xSocket,
                                        uint16_t usPort )
    {
        struct freertos_sockaddr xAddress;
        BaseType_t xReturn;

        /* Auto bind the port. */
        ( void ) memset( &( xAddress ), 0, sizeof( xAddress ) );
        xAddress.sin_family = FREERTOS_AF_INET;
        xAddress.sin_port = usPort;

        xReturn = FreeRTOS_bind( xSocket, &xAddress, sizeof( xAddress ) );

        return xReturn;
    }

/**
 * @brief Create a socket and bind it to the standard DNS port number.
 * @return The created socket - or NULL.
 */
    static Socket_t prvCreateDNSSocket()
    {
        Socket_t xSocket;

        /* This must be the first time this function has been called.  Create
         * the socket. */
        xSocket = FreeRTOS_socket( FREERTOS_AF_INET, FREERTOS_SOCK_DGRAM, FREERTOS_IPPROTO_UDP );

        if( xSocketValid( xSocket ) == pdFALSE )
        {
            /* There was an error, return NULL. */
            xSocket = NULL;
        }

        return xSocket;
    }
/*-----------------------------------------------------------*/

    #if ( ( ipconfigUSE_NBNS == 1 ) || ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) )

/**
 * @brief Send a DNS message to be used in NBNS or LLMNR
 *
 * @param[in] pxNetworkBuffer: The network buffer descriptor with the DNS message.
 * @param[in] lNetLength: The length of the DNS message.
 */
        static void prvReplyDNSMessage( NetworkBufferDescriptor_t * pxNetworkBuffer,
                                        BaseType_t lNetLength )
        {
            UDPPacket_t * pxUDPPacket;
            IPHeader_t * pxIPHeader;
            UDPHeader_t * pxUDPHeader;
            NetworkEndPoint_t * pxEndPoint = prvFindEndPointOnNetMask( pxNetworkBuffer );
            size_t uxDataLength;

            pxUDPPacket = ipCAST_PTR_TO_TYPE_PTR( UDPPacket_t, pxNetworkBuffer->pucEthernetBuffer );
            pxIPHeader = &pxUDPPacket->xIPHeader;

            #if ( ipconfigUSE_IPv6 != 0 )
                if( ( pxIPHeader->ucVersionHeaderLength & 0xf0U ) == 0x60U )
                {
                    UDPPacket_IPv6_t * xUDPPacket_IPv6;
                    IPHeader_IPv6_t * pxIPHeader_IPv6;

                    xUDPPacket_IPv6 = ipCAST_PTR_TO_TYPE_PTR( UDPPacket_IPv6_t, pxNetworkBuffer->pucEthernetBuffer );
                    pxIPHeader_IPv6 = &( xUDPPacket_IPv6->xIPHeader );
                    pxUDPHeader = &xUDPPacket_IPv6->xUDPHeader;

                    pxIPHeader_IPv6->usPayloadLength = FreeRTOS_htons( ( uint16_t ) lNetLength + ipSIZE_OF_UDP_HEADER );

                    {
                        ( void ) memcpy( pxIPHeader_IPv6->xDestinationAddress.ucBytes, pxIPHeader_IPv6->xSourceAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
                        ( void ) memcpy( pxIPHeader_IPv6->xSourceAddress.ucBytes, pxEndPoint->ipv6_settings.xIPAddress.ucBytes, ipSIZE_OF_IPv6_ADDRESS );
                    }

                    xUDPPacket_IPv6->xUDPHeader.usLength = FreeRTOS_htons( ( uint16_t ) lNetLength + ipSIZE_OF_UDP_HEADER );
                    vFlip_16( pxUDPHeader->usSourcePort, pxUDPHeader->usDestinationPort );
                    uxDataLength = ( size_t ) lNetLength + ipSIZE_OF_IPv6_HEADER + ipSIZE_OF_UDP_HEADER + ipSIZE_OF_ETH_HEADER;
                }
                else
            #endif /* ipconfigUSE_IPv6 */
            {
                pxUDPHeader = &pxUDPPacket->xUDPHeader;
                /* HT: started using defines like 'ipSIZE_OF_xxx' */
                pxIPHeader->usLength = FreeRTOS_htons( ( uint16_t ) lNetLength + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_UDP_HEADER );

                /* HT:endian: should not be translated, copying from packet to packet */
                if( pxIPHeader->ulDestinationIPAddress == ipMDNS_IP_ADDRESS )
                {
                    pxIPHeader->ulDestinationIPAddress = ipMDNS_IP_ADDRESS;
                }
                else
                {
                    pxIPHeader->ulDestinationIPAddress = pxIPHeader->ulSourceIPAddress;
                }

                pxIPHeader->ulSourceIPAddress = ( pxEndPoint != NULL ) ? pxEndPoint->ipv4_settings.ulIPAddress : 0U;
                pxIPHeader->ucTimeToLive = ipconfigUDP_TIME_TO_LIVE;
                pxIPHeader->usIdentification = FreeRTOS_htons( usPacketIdentifier );
                usPacketIdentifier++;
                pxUDPHeader->usLength = FreeRTOS_htons( ( uint32_t ) lNetLength + ipSIZE_OF_UDP_HEADER );
                vFlip_16( pxUDPHeader->usSourcePort, pxUDPHeader->usDestinationPort );

                /* Important: tell NIC driver how many bytes must be sent */
                uxDataLength = ( ( size_t ) lNetLength ) + ipSIZE_OF_IPv4_HEADER + ipSIZE_OF_UDP_HEADER + ipSIZE_OF_ETH_HEADER;
            }

            #if ( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 )
                {
                    #if ( ipconfigUSE_IPv6 != 0 )
                        /* IPv6 IP-headers have no checksum field. */
                        if( ( pxIPHeader->ucVersionHeaderLength & 0xf0U ) != 0x60U )
                    #endif
                    {
                        /* Calculate the IP header checksum. */
                        pxIPHeader->usHeaderChecksum = 0U;
                        pxIPHeader->usHeaderChecksum = usGenerateChecksum( 0U, ( uint8_t * ) &( pxIPHeader->ucVersionHeaderLength ), ipSIZE_OF_IPv4_HEADER );
                        pxIPHeader->usHeaderChecksum = ~FreeRTOS_htons( pxIPHeader->usHeaderChecksum );
                    }

                    /* calculate the UDP checksum for outgoing package */
                    ( void ) usGenerateProtocolChecksum( ( uint8_t * ) pxUDPPacket, uxDataLength, pdTRUE );
                }
            #endif /* ( ipconfigDRIVER_INCLUDED_TX_IP_CHECKSUM == 0 ) */

            /* Important: tell NIC driver how many bytes must be sent */
            pxNetworkBuffer->xDataLength = uxDataLength;

            /* This function will fill in the eth addresses and send the packet */
            vReturnEthernetFrame( pxNetworkBuffer, pdFALSE );
        }

    #endif /* ( ( ipconfigUSE_NBNS == 1 ) || ( ipconfigUSE_LLMNR == 1 ) || ( ipconfigUSE_MDNS == 1 ) ) */
/*-----------------------------------------------------------*/

    #if ( ipconfigUSE_DNS_CACHE == 1 )

/**
 * @brief Copy DNS cache entries at xIndex to a linked struct addrinfo.
 * @param[in] xIndex: The index from where entries must be copied.
 * @param[out] ppxAddressInfo: Target to store the DNS entries.
 */
        static void prvReadDNSCache( BaseType_t xIndex,
                                     struct freertos_addrinfo ** ppxAddressInfo )
        {
            size_t uxIPAddressIndex;
            size_t uxNumIPAddresses = 1U;
            IPv46_Address_t * pxAddresses;
            struct freertos_addrinfo * pxNewAddress;
            struct freertos_addrinfo * pxLastAddress;
            struct freertos_addrinfo ** ppxLastAddress = &( pxLastAddress );

            #if ( ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY > 1 )
                uxNumIPAddresses = ( size_t ) xDNSCache[ xIndex ].ucNumIPAddresses;

                if( uxNumIPAddresses > ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY )
                {
                    /* Make this a configASSERT()? */
                    uxNumIPAddresses = ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY;
                }
            #endif /* ( ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY > 1 ) */

            for( uxIPAddressIndex = 0; uxIPAddressIndex < uxNumIPAddresses; uxIPAddressIndex++ )
            {
                pxAddresses = &( xDNSCache[ xIndex ].xAddresses[ uxIPAddressIndex ] );

                #if ( ipconfigUSE_IPv6 != 0 )
                    if( pxAddresses->xIs_IPv6 != pdFALSE )
                    {
                        pxNewAddress = pxNew_AddrInfo( xDNSCache[ xIndex ].pcName, FREERTOS_AF_INET6, pxAddresses->xAddress_IPv6.ucBytes );
                    }
                    else
                #endif /* ( ipconfigUSE_IPv6 != 0 ) */
                {
                    uint8_t * ucBytes = ( uint8_t * ) &( pxAddresses->ulIPAddress );

                    pxNewAddress = pxNew_AddrInfo( xDNSCache[ xIndex ].pcName, FREERTOS_AF_INET4, ucBytes );
                }

                if( pxNewAddress != NULL )
                {
                    if( *( ppxAddressInfo ) == NULL )
                    {
                        /* For the first address found. */
                        *( ppxAddressInfo ) = pxNewAddress;
                    }
                    else
                    {
                        /* For the next address found. */
                        *( ppxLastAddress ) = pxNewAddress;
                    }

                    ppxLastAddress = &( pxNewAddress->ai_next );
                }
            }
        }
    #endif /* #if( ipconfigUSE_DNS_CACHE == 1 ) */
/*-----------------------------------------------------------*/

    #if ( ipconfigUSE_DNS_CACHE == 1 )

/**
 * @brief Send a DNS message to be used in NBNS or LLMNR
 *
 * @param[in] pcName: the name of the host
 * @param[in,out] pxIP: when doing a lookup, will be set, when doing an update,
 *                      will be read.
 * @param[in] ulTTL: Time To Live
 * @param[in] xLookUp: pdTRUE if a look-up is expected, pdFALSE, when the DNS cache must
 *                     be updated.
 * @param[in,out] ppxAddressInfo: A pointer to a pointer where the find results
 *                                will be stored.
 *
 * @return
 */
        static BaseType_t prvProcessDNSCache( const char * pcName,
                                              IPv46_Address_t * pxIP,
                                              uint32_t ulTTL,
                                              BaseType_t xLookUp,
                                              struct freertos_addrinfo ** ppxAddressInfo )
        {
            BaseType_t x;
            BaseType_t xFound = pdFALSE;
            uint32_t ulCurrentTimeSeconds;
            uint32_t ulIPAddressIndex = 0;

            /* Get the current time in clock-ticks. */
            ulCurrentTimeSeconds = ( uint32_t ) xTaskGetTickCount();
            /* In milliseconds. */
            ulCurrentTimeSeconds = ulCurrentTimeSeconds / portTICK_PERIOD_MS;
            /* In seconds. */
            ulCurrentTimeSeconds = ulCurrentTimeSeconds / 1000U;

            configASSERT( ( pcName != NULL ) );

            if( xLookUp != pdFALSE )
            {
                pxIP->ulIPAddress = 0U;
            }

            /* Look for a matching entry: same name and same IP-type. */
            for( x = 0; x < ( BaseType_t ) ipconfigDNS_CACHE_ENTRIES; x++ )
            {
                if( ( xDNSCache[ x ].pcName[ 0 ] != ( char ) 0 ) &&
                    #if ( ipconfigUSE_IPv6 != 0 )
                        /* IPv6 is enabled, See if the cache entry has the correct type. */
                        ( pxIP->xIs_IPv6 == xDNSCache[ x ].xAddresses[ 0 ].xIs_IPv6 ) &&
                    #endif /* ipconfigUSE_IPv6 != 0 */
                    ( strcmp( xDNSCache[ x ].pcName, pcName ) == 0 ) )
                {
                    xFound = pdTRUE;
                    break;
                }
            }     /* for( x = 0; x < ( BaseType_t ) ipconfigDNS_CACHE_ENTRIES; x++ ) */

            if( xFound == pdTRUE )
            {
                /* Is this function called for a lookup or to add/update an IP address? */
                if( xLookUp == pdTRUE )
                {
                    /* Confirm that the record is still fresh. */
                    if( ulCurrentTimeSeconds < ( xDNSCache[ x ].ulTimeWhenAddedInSeconds + FreeRTOS_ntohl( xDNSCache[ x ].ulTTL ) ) )
                    {
                        #if ( ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY > 1 )
                            uint8_t ucIndex;
                            /* The ucCurrentIPAddress value increments without bound and will rollover, */
                            /*  modulo it by the number of IP addresses to keep it in range.     */
                            /*  Also perform a final modulo by the max number of IP addresses    */
                            /*  per DNS cache entry to prevent out-of-bounds access in the event */
                            /*  that ucNumIPAddresses has been corrupted.                        */
                            ucIndex = xDNSCache[ x ].ucCurrentIPAddress % xDNSCache[ x ].ucNumIPAddresses;
                            ucIndex = ucIndex % ( uint8_t ) ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY;
                            ulIPAddressIndex = ucIndex;

                            xDNSCache[ x ].ucCurrentIPAddress++;
                        #endif /* ( ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY > 1 ) */
                        ( void ) memcpy( pxIP, &( xDNSCache[ x ].xAddresses[ ulIPAddressIndex ] ), sizeof( *pxIP ) );

                        if( ppxAddressInfo != NULL )
                        {
                            /* Copy all entries from position 'x' to a linked struct addrinfo. */
                            prvReadDNSCache( x, ppxAddressInfo );
                        }
                    }
                    else
                    {
                        /* Age out the old cached record. */
                        xDNSCache[ x ].pcName[ 0 ] = ( char ) 0;
                    }
                }
                else
                {
                    #if ( ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY > 1 )
                        if( xDNSCache[ x ].ucNumIPAddresses < ( uint8_t ) ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY )
                        {
                            /* If more answers exist than there are IP address storage slots */
                            /* they will overwrite entry 0 */

                            ulIPAddressIndex = xDNSCache[ x ].ucNumIPAddresses;
                            xDNSCache[ x ].ucNumIPAddresses++;
                        }
                    #endif /* ( ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY > 1 ) */
                    ( void ) memcpy( &( xDNSCache[ x ].xAddresses[ ulIPAddressIndex ] ), pxIP, sizeof( *pxIP ) );
                    xDNSCache[ x ].ulTTL = ulTTL;
                    xDNSCache[ x ].ulTimeWhenAddedInSeconds = ulCurrentTimeSeconds;
                }
            }     /* if( xFound != pdTRUE ) */
            else
            {
                /* Add or update the item. */
                if( strlen( pcName ) < ( size_t ) ipconfigDNS_CACHE_NAME_LENGTH )
                {
                    ( void ) strcpy( xDNSCache[ xFreeDNSEntry ].pcName, pcName );
                    ( void ) memcpy( &( xDNSCache[ xFreeDNSEntry ].xAddresses[ 0 ] ), pxIP, sizeof( *pxIP ) );
                    xDNSCache[ xFreeDNSEntry ].ulTTL = ulTTL;
                    xDNSCache[ xFreeDNSEntry ].ulTimeWhenAddedInSeconds = ulCurrentTimeSeconds;
                    #if ( ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY > 1 )
                        xDNSCache[ xFreeDNSEntry ].ucNumIPAddresses = 1;
                        xDNSCache[ xFreeDNSEntry ].ucCurrentIPAddress = 0;

                        /* Initialize all remaining IP addresses in this entry to 0 */
                        ( void ) memset( &xDNSCache[ xFreeDNSEntry ].xAddresses[ 1 ],
                                         0,
                                         sizeof( xDNSCache[ xFreeDNSEntry ].xAddresses[ 1 ] ) *
                                         ( ( uint32_t ) ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY - 1U ) );
                    #endif /* ( ipconfigDNS_CACHE_ADDRESSES_PER_ENTRY > 1 ) */

                    if( xFreeDNSEntry < ( BaseType_t ) ( ipconfigDNS_CACHE_ENTRIES - 1 ) )
                    {
                        xFreeDNSEntry++;
                    }
                    else
                    {
                        xFreeDNSEntry = 0;
                    }
                }
            }

            return xFound;
        }

    #endif /* ipconfigUSE_DNS_CACHE */

#endif /* ipconfigUSE_DNS != 0 */

/*-----------------------------------------------------------*/

/* Provide access to private members for testing. */
#ifdef FREERTOS_ENABLE_UNIT_TESTS
    #include "freertos_tcp_test_access_dns_define.h"
#endif
