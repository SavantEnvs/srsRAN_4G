#include "common.h"
#include "srsran/asn1/liblte_mme.h"

#include <cstring>

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
  mayhem_quiet_logs();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  // liblte's message buffer is fixed-size; a longer PDU is outside its contract.
  if (size >= LIBLTE_MAX_MSG_SIZE_BYTES) {
    return -1;
  }
  LIBLTE_BYTE_MSG_STRUCT msg;
  memset(&msg, 0, sizeof(msg));
  if (size > 0) {
    memcpy(msg.msg, data, size);
  }
  msg.N_bytes = size;

  uint8             pd       = 0;
  uint8             msg_type = 0;
  LIBLTE_ERROR_ENUM err      = LIBLTE_ERROR_INVALID_INPUTS;

  liblte_mme_parse_msg_header(&msg, &pd, &msg_type);

  switch (msg_type) {
    case LIBLTE_MME_MSG_TYPE_ATTACH_REQUEST: {
      LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT attach_req;
      err = liblte_mme_unpack_attach_request_msg(&msg, &attach_req);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ATTACH_ACCEPT: {
      LIBLTE_MME_ATTACH_ACCEPT_MSG_STRUCT attach_accept;
      err = liblte_mme_unpack_attach_accept_msg(&msg, &attach_accept);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ATTACH_COMPLETE: {
      LIBLTE_MME_ATTACH_COMPLETE_MSG_STRUCT attach_complete;
      err = liblte_mme_unpack_attach_complete_msg(&msg, &attach_complete);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ATTACH_REJECT: {
      LIBLTE_MME_ATTACH_REJECT_MSG_STRUCT attach_reject;
      err = liblte_mme_unpack_attach_reject_msg(&msg, &attach_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_DETACH_REQUEST: {
      LIBLTE_MME_DETACH_REQUEST_MSG_STRUCT detach_request;
      err = liblte_mme_unpack_detach_request_msg(&msg, &detach_request);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_DETACH_ACCEPT: {
      LIBLTE_MME_DETACH_ACCEPT_MSG_STRUCT detach_accept;
      err = liblte_mme_unpack_detach_accept_msg(&msg, &detach_accept);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_ACCEPT: {
      LIBLTE_MME_TRACKING_AREA_UPDATE_ACCEPT_MSG_STRUCT ta_update_accept;
      err = liblte_mme_unpack_tracking_area_update_accept_msg(&msg, &ta_update_accept);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_REJECT: {
      LIBLTE_MME_TRACKING_AREA_UPDATE_REJECT_MSG_STRUCT ta_update_reject;
      err = liblte_mme_unpack_tracking_area_update_reject_msg(&msg, &ta_update_reject);
      break;
    }
    
    case LIBLTE_MME_MSG_TYPE_TRACKING_AREA_UPDATE_COMPLETE: {
      LIBLTE_MME_TRACKING_AREA_UPDATE_COMPLETE_MSG_STRUCT ta_update_complete;
      err = liblte_mme_unpack_tracking_area_update_complete_msg(&msg, &ta_update_complete);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_EXTENDED_SERVICE_REQUEST: {
      LIBLTE_MME_EXTENDED_SERVICE_REQUEST_MSG_STRUCT ext_service;
      err = liblte_mme_unpack_extended_service_request_msg(&msg, &ext_service);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_SERVICE_REJECT: { // Service reject
      LIBLTE_MME_SERVICE_REJECT_MSG_STRUCT service_reject;
      err = liblte_mme_unpack_service_reject_msg(&msg, &service_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMMAND: { // GUTI reallocation command
      LIBLTE_MME_GUTI_REALLOCATION_COMMAND_MSG_STRUCT guti_realloc_cmd;
      err = liblte_mme_unpack_guti_reallocation_command_msg(&msg, &guti_realloc_cmd);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_GUTI_REALLOCATION_COMPLETE: {
      LIBLTE_MME_GUTI_REALLOCATION_COMPLETE_MSG_STRUCT guti_realloc_cmplt;
      err = liblte_mme_unpack_guti_reallocation_complete_msg(&msg, &guti_realloc_cmplt);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REJECT: {
      LIBLTE_MME_AUTHENTICATION_REJECT_MSG_STRUCT auth_reject;
      err = liblte_mme_unpack_authentication_reject_msg(&msg, &auth_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_RESPONSE: {
      LIBLTE_MME_AUTHENTICATION_RESPONSE_MSG_STRUCT auth_response;
      err = liblte_mme_unpack_authentication_response_msg(&msg, &auth_response);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_AUTHENTICATION_REQUEST: {
      LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT auth_req;
      err = liblte_mme_unpack_authentication_request_msg(&msg, &auth_req);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_IDENTITY_REQUEST: {
      LIBLTE_MME_ID_REQUEST_MSG_STRUCT identity_request;
      err = liblte_mme_unpack_identity_request_msg(&msg, &identity_request);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_IDENTITY_RESPONSE: {
      LIBLTE_MME_ID_RESPONSE_MSG_STRUCT identity_response;
      err = liblte_mme_unpack_identity_response_msg(&msg, &identity_response);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMMAND: {
      LIBLTE_MME_SECURITY_MODE_COMMAND_MSG_STRUCT sec_mode_cmd;
      err = liblte_mme_unpack_security_mode_command_msg(&msg, &sec_mode_cmd);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_COMPLETE: {
      LIBLTE_MME_SECURITY_MODE_COMPLETE_MSG_STRUCT sec_mode_cmplt;
      err = liblte_mme_unpack_security_mode_complete_msg(&msg, &sec_mode_cmplt);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_SECURITY_MODE_REJECT: {
      LIBLTE_MME_SECURITY_MODE_REJECT_MSG_STRUCT sec_mode_reject;
      err = liblte_mme_unpack_security_mode_reject_msg(&msg, &sec_mode_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_EMM_INFORMATION: {
      LIBLTE_MME_EMM_INFORMATION_MSG_STRUCT emm_info;
      err = liblte_mme_unpack_emm_information_msg(&msg, &emm_info);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_EMM_STATUS: {
      LIBLTE_MME_EMM_STATUS_MSG_STRUCT emm_status;
      err = liblte_mme_unpack_emm_status_msg(&msg, &emm_status);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_DOWNLINK_NAS_TRANSPORT: {
      LIBLTE_MME_DOWNLINK_NAS_TRANSPORT_MSG_STRUCT dl_nas_transport;
      err = liblte_mme_unpack_downlink_nas_transport_msg(&msg, &dl_nas_transport);
      break;
    }
    
    case LIBLTE_MME_MSG_TYPE_DOWNLINK_GENERIC_NAS_TRANSPORT: {
      LIBLTE_MME_DOWNLINK_GENERIC_NAS_TRANSPORT_MSG_STRUCT dl_generic_nas_transport;
      err = liblte_mme_unpack_downlink_generic_nas_transport_msg(&msg, &dl_generic_nas_transport);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_UPLINK_GENERIC_NAS_TRANSPORT: {
      LIBLTE_MME_UPLINK_GENERIC_NAS_TRANSPORT_MSG_STRUCT ul_generic_nas_transport;
      err = liblte_mme_unpack_uplink_generic_nas_transport_msg(&msg, &ul_generic_nas_transport);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST: {
      LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_def_eps_bearer;
      err = liblte_mme_unpack_activate_default_eps_bearer_context_request_msg(&msg, &act_def_eps_bearer);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT: {
      LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT_MSG_STRUCT act_def_eps_bearer_accept;
      err = liblte_mme_unpack_activate_default_eps_bearer_context_accept_msg(&msg, &act_def_eps_bearer_accept);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT: {
      LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT_MSG_STRUCT act_def_eps_bearer_reject;
      err = liblte_mme_unpack_activate_default_eps_bearer_context_reject_msg(&msg, &act_def_eps_bearer_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST: {
      LIBLTE_MME_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_ded_eps_bearer_request;
      err = liblte_mme_unpack_activate_dedicated_eps_bearer_context_request_msg(&msg, &act_ded_eps_bearer_request);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT: {
      LIBLTE_MME_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT_MSG_STRUCT act_ded_eps_bearer_accept;
      err = liblte_mme_unpack_activate_dedicated_eps_bearer_context_accept_msg(&msg, &act_ded_eps_bearer_accept);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT: {
      LIBLTE_MME_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT_MSG_STRUCT act_ded_eps_bearer_reject;
      err = liblte_mme_unpack_activate_dedicated_eps_bearer_context_reject_msg(&msg, &act_ded_eps_bearer_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REQUEST: {
      LIBLTE_MME_MODIFY_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT mod_eps_bearer_request;
      err = liblte_mme_unpack_modify_eps_bearer_context_request_msg(&msg, &mod_eps_bearer_request);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_ACCEPT: {
      LIBLTE_MME_MODIFY_EPS_BEARER_CONTEXT_ACCEPT_MSG_STRUCT mod_eps_bearer_accept;
      err = liblte_mme_unpack_modify_eps_bearer_context_accept_msg(&msg, &mod_eps_bearer_accept);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_MODIFY_EPS_BEARER_CONTEXT_REJECT: {
      LIBLTE_MME_MODIFY_EPS_BEARER_CONTEXT_REJECT_MSG_STRUCT mod_eps_bearer_reject;
      err = liblte_mme_unpack_modify_eps_bearer_context_reject_msg(&msg, &mod_eps_bearer_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST: {
      LIBLTE_MME_DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT deactivate_eps_bearer_request;
      err = liblte_mme_unpack_deactivate_eps_bearer_context_request_msg(&msg, &deactivate_eps_bearer_request);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT: {
      LIBLTE_MME_DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT_MSG_STRUCT deactivate_eps_bearer_accept;
      err = liblte_mme_unpack_deactivate_eps_bearer_context_accept_msg(&msg, &deactivate_eps_bearer_accept);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REQUEST: {
      LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT pdn_connectivity_request;
      err = liblte_mme_unpack_pdn_connectivity_request_msg(&msg, &pdn_connectivity_request);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_PDN_CONNECTIVITY_REJECT: {
      LIBLTE_MME_PDN_CONNECTIVITY_REJECT_MSG_STRUCT pdn_connectivity_reject;
      err = liblte_mme_unpack_pdn_connectivity_reject_msg(&msg, &pdn_connectivity_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REQUEST: {
      LIBLTE_MME_PDN_DISCONNECT_REQUEST_MSG_STRUCT pdn_disconnect_request;
      err = liblte_mme_unpack_pdn_disconnect_request_msg(&msg, &pdn_disconnect_request);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_PDN_DISCONNECT_REJECT: {
      LIBLTE_MME_PDN_DISCONNECT_REJECT_MSG_STRUCT pdn_disconnect_reject;
      err = liblte_mme_unpack_pdn_disconnect_reject_msg(&msg, &pdn_disconnect_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REQUEST: {
      LIBLTE_MME_BEARER_RESOURCE_ALLOCATION_REQUEST_MSG_STRUCT rsrc_alloc_request;
      err = liblte_mme_unpack_bearer_resource_allocation_request_msg(&msg, &rsrc_alloc_request);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_ALLOCATION_REJECT: {
      LIBLTE_MME_BEARER_RESOURCE_ALLOCATION_REJECT_MSG_STRUCT rsrc_alloc_reject;
      err = liblte_mme_unpack_bearer_resource_allocation_reject_msg(&msg, &rsrc_alloc_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REQUEST: {
      LIBLTE_MME_BEARER_RESOURCE_MODIFICATION_REQUEST_MSG_STRUCT rsrc_mod_request;
      err = liblte_mme_unpack_bearer_resource_modification_request_msg(&msg, &rsrc_mod_request);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_BEARER_RESOURCE_MODIFICATION_REJECT: {
      LIBLTE_MME_BEARER_RESOURCE_MODIFICATION_REJECT_MSG_STRUCT rsrc_mod_reject;
      err = liblte_mme_unpack_bearer_resource_modification_reject_msg(&msg, &rsrc_mod_reject);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_REQUEST: {
      LIBLTE_MME_ESM_INFORMATION_REQUEST_MSG_STRUCT esm_information_request;
      err = liblte_mme_unpack_esm_information_request_msg(&msg, &esm_information_request);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ESM_INFORMATION_RESPONSE: {
      LIBLTE_MME_ESM_INFORMATION_RESPONSE_MSG_STRUCT esm_information_response;
      err = liblte_mme_unpack_esm_information_response_msg(&msg, &esm_information_response);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_NOTIFICATION: {
      LIBLTE_MME_NOTIFICATION_MSG_STRUCT notification;
      err = liblte_mme_unpack_notification_msg(&msg, &notification);
      break;
    }
    case LIBLTE_MME_MSG_TYPE_ESM_STATUS: {
      LIBLTE_MME_ESM_STATUS_MSG_STRUCT esm_status;
      err = liblte_mme_unpack_esm_status_msg(&msg, &esm_status);
      break;
    }
    default:
      return -1;
  }
  return err == LIBLTE_SUCCESS ? 0 : -1;
}
