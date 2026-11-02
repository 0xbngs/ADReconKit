/*
 * adsi_interfaces.h — UAC / ADCS flag constants used by recon modules.
 * LDAP itself goes through wldap32 (see bofdefs.h); this header has no COM.
 */

#ifndef _ADSI_INTERFACES_H_
#define _ADSI_INTERFACES_H_

#define CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT  0x00000001

#define UAC_ACCOUNTDISABLE          0x00000002  /* 2        */
#define UAC_PASSWD_NOTREQD          0x00000020  /* 32       */
#define UAC_SERVER_TRUST_ACCOUNT    0x00002000  /* 8192     */
#define UAC_DONT_EXPIRE_PASSWORD    0x00010000  /* 65536    */
#define UAC_DONT_REQ_PREAUTH        0x00400000  /* 4194304  */
#define UAC_PARTIAL_SECRETS_ACCOUNT 0x04000000  /* RODC     */

#endif /* _ADSI_INTERFACES_H_ */
