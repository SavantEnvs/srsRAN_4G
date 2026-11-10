// Known-answer probe: decodes fixed PDUs (vectors taken from srsRAN's own unit tests, plus RLC/GTP-U/MAC
// vectors worked out from the 3GPP layouts) through the real parsers and prints the decoded fields, one
// "key=value" per line. mayhem/test.sh compares the output with golden values.
#include "srsran/asn1/asn1_utils.h"
#include "srsran/asn1/liblte_mme.h"
#include "srsran/asn1/nas_5g_msg.h"
#include "srsran/asn1/ngap.h"
#include "srsran/asn1/rrc.h"
#include "srsran/asn1/s1ap.h"
#include "srsran/common/byte_buffer.h"
#include "srsran/mac/mac_rar_pdu_nr.h"
#include "srsran/mac/mac_sch_pdu_nr.h"
#include "srsran/rlc/rlc_am_lte_packing.h"
#include "srsran/rlc/rlc_am_nr_packing.h"
#include "srsran/upper/gtpu.h"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace asn1;

static void ngap_kat()
{
  const uint8_t msg[] = {0x00, 0x15, 0x00, 0x30, 0x00, 0x00, 0x04, 0x00, 0x1b, 0x00, 0x09, 0x00, 0x00,
                         0xf1, 0x10, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x52, 0x40, 0x06, 0x01, 0x80,
                         0x67, 0x6e, 0x62, 0x31, 0x00, 0x66, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x75,
                         0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x15, 0x40, 0x01, 0x60};
  cbit_ref      bref(msg, sizeof(msg));
  ngap::ngap_pdu_c pdu;
  printf("ngap.unpack=%d\n", (int)pdu.unpack(bref));
  printf("ngap.proc_code=%d\n", (int)pdu.init_msg().proc_code);
  auto& setup = pdu.init_msg().value.ng_setup_request();
  printf("ngap.gnb_id=%u\n", (unsigned)setup->global_ran_node_id.value.global_gnb_id().gnb_id.gnb_id().to_number());
  printf("ngap.plmn=0x%x\n", (unsigned)setup->global_ran_node_id.value.global_gnb_id().plmn_id.to_number());
  printf("ngap.tac=0x%x\n", (unsigned)setup->supported_ta_list.value[0].tac.to_number());
  printf("ngap.consumed_bytes=%d\n", (int)ceil(bref.distance_bytes()));
}

static void s1ap_kat()
{
  const uint8_t msg[] = {0x00, 0x11, 0x00, 0x2d, 0x00, 0x00, 0x04, 0x00, 0x3b, 0x00, 0x08, 0x00, 0x09,
                         0xf1, 0x07, 0x00, 0x00, 0x19, 0xb0, 0x00, 0x3c, 0x40, 0x0a, 0x03, 0x80, 0x65,
                         0x6e, 0x62, 0x30, 0x30, 0x31, 0x39, 0x62, 0x00, 0x40, 0x00, 0x07, 0x00, 0x00,
                         0x01, 0xc0, 0x09, 0xf1, 0x07, 0x00, 0x89, 0x40, 0x01, 0x40};
  cbit_ref      bref(msg, sizeof(msg));
  s1ap::s1ap_pdu_c pdu;
  printf("s1ap.unpack=%d\n", (int)pdu.unpack(bref));
  printf("s1ap.proc_code=%d\n", (int)pdu.init_msg().proc_code);
  auto& req = pdu.init_msg().value.s1_setup_request();
  printf("s1ap.enb_id=0x%x\n", (unsigned)req->global_enb_id.value.enb_id.macro_enb_id().to_number());
  printf("s1ap.enb_name=%s\n", req->enbname.value.to_string().c_str());
}

static void rrc_kat()
{
  const uint8_t msg[] = {0x60, 0x12, 0x98, 0x0b, 0xfd, 0xd2, 0x04, 0xfa, 0x18, 0x3e, 0xd5, 0xe6, 0xc2,
                         0x59, 0x90, 0xc1, 0xa6, 0x00, 0x01, 0x31, 0x40, 0x42, 0x50, 0x80, 0x00, 0xf8};
  cbit_ref      bref(msg, sizeof(msg));
  rrc::dl_ccch_msg_s dl_ccch;
  printf("rrc.unpack=%d\n", (int)dl_ccch.unpack(bref));
  printf("rrc.is_setup=%d\n", (int)(dl_ccch.msg.c1().type() == rrc::dl_ccch_msg_type_c::c1_c_::types::rrc_conn_setup));
  auto& setup = dl_ccch.msg.c1().rrc_conn_setup();
  printf("rrc.transaction_id=%d\n", (int)setup.rrc_transaction_id);
  printf("rrc.phys_cfg_ded_present=%d\n", (int)setup.crit_exts.c1().rrc_conn_setup_r8().rr_cfg_ded.phys_cfg_ded_present);
  printf("rrc.consumed_bytes=%d\n", (int)ceil(bref.distance_bytes()));
}

static void nas_5g_kat()
{
  const std::vector<uint8_t> msg = {0x7e, 0x00, 0x41, 0x79, 0x00, 0x0b, 0xf2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x2e, 0x02, 0xf0, 0xf0, 0x17, 0x07, 0xf0, 0xf0, 0xc0, 0xc0, 0x01, 0x80, 0x30};
  using namespace srsran::nas_5g;
  nas_5gs_msg nas;
  printf("nas5g.unpack=%d\n", (int)nas.unpack(msg));
  printf("nas5g.is_5gmm=%d\n", (int)(nas.hdr.extended_protocol_discriminator == nas_5gs_hdr::extended_protocol_discriminator_5gmm));
  printf("nas5g.is_plain=%d\n", (int)(nas.hdr.security_header_type == nas_5gs_hdr::plain_5gs_nas_message));
  printf("nas5g.is_registration_request=%d\n", (int)(nas.hdr.message_type == msg_types::options::registration_request));
  registration_request_t& rr = nas.registration_request();
  printf("nas5g.initial_registration=%d\n",
         (int)(rr.registration_type_5gs.registration_type == registration_type_5gs_t::registration_type_type_::options::initial_registration));
  printf("nas5g.follow_on_pending=%d\n",
         (int)(rr.registration_type_5gs.follow_on_request_bit == registration_type_5gs_t::follow_on_request_bit_type_::options::follow_on_request_pending));
  printf("nas5g.guti=%d\n", (int)(rr.mobile_identity_5gs.type() == mobile_identity_5gs_t::identity_types_::options::guti_5g));
  printf("nas5g.sec_cap_present=%d\n", (int)rr.ue_security_capability_present);
  printf("nas5g.ea1=%d ea4=%d ia3=%d ia4=%d\n",
         (int)rr.ue_security_capability.ea1_128_5g_supported,
         (int)rr.ue_security_capability.ea4_5g_supported,
         (int)rr.ue_security_capability.ia3_128_5g_supported,
         (int)rr.ue_security_capability.ia4_5g_supported);
}

static void eps_nas_kat()
{
  const uint8_t          msg[] = {0x27, 0xae, 0x80, 0xc8, 0xf9, 0x06, 0x07, 0x68, 0x01, 0x00, 0x06, 0xf0, 0x00, 0x00, 0x00, 0x08, 0x70};
  LIBLTE_BYTE_MSG_STRUCT buf   = {};
  memcpy(buf.msg, msg, sizeof(msg));
  buf.N_bytes = sizeof(msg);
  LIBLTE_MME_DOWNLINK_GENERIC_NAS_TRANSPORT_MSG_STRUCT dl = {};
  printf("epsnas.unpack=%d\n", (int)liblte_mme_unpack_downlink_generic_nas_transport_msg(&buf, &dl));
  printf("epsnas.cont_type=%d\n", (int)dl.generic_msg_cont_type);
  printf("epsnas.cont_len=%d\n", (int)dl.generic_msg_cont.N_bytes);
  printf("epsnas.add_info=%d\n", (int)dl.add_info_present);
}

static void mac_nr_kat()
{
  // MAC PDU: ConRes CE, 8-byte SDU on LCID 4, padding
  const uint8_t tv[] = {0x3e, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x04, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x3f, 0x00};
  srsran::mac_sch_pdu_nr pdu;
  printf("macnr.unpack=%d\n", pdu.unpack(tv, sizeof(tv)));
  printf("macnr.subpdus=%u\n", pdu.get_num_subpdus());
  for (uint32_t i = 0; i < pdu.get_num_subpdus(); ++i) {
    printf("macnr.subpdu%u=lcid:%u,sdu_len:%u,total_len:%u\n",
           i,
           pdu.get_subpdu(i).get_lcid(),
           pdu.get_subpdu(i).get_sdu_length(),
           pdu.get_subpdu(i).get_total_length());
  }
}

static void rlc_kat()
{
  // LTE AMD PDU header: D/C=1, RF=0, P=1, FI=0, E=0, SN=0x123
  uint8_t              amd[] = {0xa1, 0x23, 0xde, 0xad};
  uint8_t*             p     = amd;
  uint32_t             n     = sizeof(amd);
  srsran::rlc_amd_pdu_header_t hdr;
  srsran::rlc_am_read_data_pdu_header(&p, &n, &hdr);
  printf("rlc.lte_data.sn=0x%x\n", (unsigned)hdr.sn);
  printf("rlc.lte_data.p=%d\n", (int)hdr.p);
  printf("rlc.lte_data.remaining=%u\n", n);

  // LTE status PDU: D/C=0, CPT=000, ACK_SN=10, E1=0
  uint8_t               st[] = {0x00, 0x28, 0x00};
  srsran::rlc_status_pdu_t status;
  srsran::rlc_am_read_status_pdu(st, sizeof(st), &status);
  printf("rlc.lte_status.ack_sn=%u\n", (unsigned)status.ack_sn);
  printf("rlc.lte_status.nacks=%u\n", status.N_nack);

  // NR status PDU, 12-bit SN: ACK_SN=10, one NACK_SN=5
  uint8_t                       nst[] = {0x00, 0x0a, 0x80, 0x00, 0x50};
  srsran::rlc_am_nr_status_pdu_t nstatus(srsran::rlc_am_nr_sn_size_t::size12bits);
  srsran::rlc_am_nr_read_status_pdu(nst, sizeof(nst), srsran::rlc_am_nr_sn_size_t::size12bits, &nstatus);
  printf("rlc.nr_status.ack_sn=%u\n", nstatus.ack_sn);
  printf("rlc.nr_status.nacks=%zu\n", nstatus.nacks.size());
  if (!nstatus.nacks.empty()) {
    printf("rlc.nr_status.nack0_sn=%u\n", nstatus.nacks[0].nack_sn);
  }

  // NR data PDU header, 12-bit SN, complete SDU (SI=0), polling set, SN=0x0ab
  uint8_t                      nd[] = {0xc0, 0xab, 0x01};
  srsran::rlc_am_nr_pdu_header_t nh;
  uint32_t hlen = srsran::rlc_am_nr_read_data_pdu_header(nd, sizeof(nd), srsran::rlc_am_nr_sn_size_t::size12bits, &nh);
  printf("rlc.nr_data.header_len=%u\n", hlen);
  printf("rlc.nr_data.sn=0x%x\n", nh.sn);
  printf("rlc.nr_data.p=%d\n", (int)nh.p);
}

static void gtpu_kat()
{
  const uint8_t pkt[] = {0x30, 0xff, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0xca, 0xfe, 0xba, 0xbe};
  auto          pdu   = srsran::make_byte_buffer();
  memcpy(pdu->msg, pkt, sizeof(pkt));
  pdu->N_bytes = sizeof(pkt);
  srsran::gtpu_header_t header;
  printf("gtpu.read=%d\n", (int)srsran::gtpu_read_header(pdu.get(), &header, srslog::fetch_basic_logger("GTPU")));
  printf("gtpu.teid=0x%x\n", header.teid);
  printf("gtpu.msg_type=0x%x\n", (unsigned)header.message_type);
  printf("gtpu.length=%u\n", (unsigned)header.length);
  printf("gtpu.payload_bytes=%u\n", pdu->N_bytes);
}

int main()
{
  srslog::fetch_basic_logger("GTPU").set_level(srslog::basic_levels::none);
  ngap_kat();
  s1ap_kat();
  rrc_kat();
  nas_5g_kat();
  eps_nas_kat();
  mac_nr_kat();
  rlc_kat();
  gtpu_kat();
  return 0;
}
