// Copyright (c) 2014-2024, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "include_base_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "misc_language.h"

using namespace cryptonote;

/* Fixed keys that correspond to the Ledger app-monero testing */
const uint8_t sender_public_spend_key[32] =   {0xda, 0xe4, 0x1d, 0x6b, 0x13, 0x56, 0x8f, 0xdd, 0x71, 0xec, 0x3d, 0x20, 0xc2, 0xf6, 0x14, 0xc6, 0x5f, 0xe8, 0x19, 0xf3, 0x6c, 0xa5, 0xda, 0x8d, 0x24, 0xdf, 0x3b, 0xd8, 0x9b, 0x2b, 0xad, 0x9d};
const uint8_t sender_public_view_key[32] =    {0x86, 0x5c, 0xbf, 0xab, 0x85, 0x2a, 0x1d, 0x1c, 0xcd, 0xfc, 0x73, 0x28, 0xe4, 0xda, 0xc9, 0x0f, 0x78, 0xfc, 0x21, 0x54, 0x25, 0x7d, 0x07, 0x52, 0x2e, 0x9b, 0x79, 0xe6, 0x37, 0x32, 0x6d, 0xfa};
const uint8_t receiver_public_spend_key[32] = {0x39, 0x2c, 0x44, 0x32, 0xe5, 0xa1, 0x5a, 0xea, 0x22, 0x7e, 0x65, 0x79, 0xa8, 0xda, 0x7d, 0x9f, 0x46, 0xfb, 0x78, 0x56, 0x5e, 0x18, 0xe7, 0xf0, 0xb2, 0x78, 0xf3, 0xf1, 0xa1, 0x46, 0x86, 0x96};
const uint8_t receiver_public_view_key[32] =  {0x2e, 0x49, 0xad, 0x29, 0xa1, 0xbf, 0xd9, 0x8a, 0xb0, 0x5c, 0x88, 0x71, 0x34, 0x63, 0xd5, 0x52, 0x12, 0x09, 0x06, 0xb1, 0xbe, 0x38, 0x02, 0x11, 0x74, 0x56, 0x95, 0x13, 0x4e, 0x18, 0x3e, 0xd0};

bool test_transaction_generation_and_ring_signature_ledger()
{

  account_base miner_acc1;
  miner_acc1.generate();
  account_base miner_acc2;
  hw::device &hwdev =  hw::get_device("Ledger");
  hwdev.set_name("Ledger");
  miner_acc2.create_from_device(hwdev);
  memcpy((void *)miner_acc2.get_keys().m_account_address.m_spend_public_key.data, sender_public_spend_key, 32);
  memcpy((void *)miner_acc2.get_keys().m_account_address.m_view_public_key.data, sender_public_view_key, 32);

  hwdev.set_mode(hw::device::TRANSACTION_CREATE_REAL);
  account_base miner_acc3;
  miner_acc3.generate();
  account_base miner_acc4;
  miner_acc4.generate();
  account_base miner_acc5;
  miner_acc5.generate();
  account_base miner_acc6;
  miner_acc6.generate();


  transaction tx_mine_1;
  construct_miner_tx(0, 0, 0, 10, 0, miner_acc1.get_keys().m_account_address, tx_mine_1);
  transaction tx_mine_2;
  construct_miner_tx(0, 0, 0, 0, 0, miner_acc2.get_keys().m_account_address, tx_mine_2);
  transaction tx_mine_3;
  construct_miner_tx(0, 0, 0, 0, 0, miner_acc3.get_keys().m_account_address, tx_mine_3);
  transaction tx_mine_4;
  construct_miner_tx(0, 0, 0, 0, 0, miner_acc4.get_keys().m_account_address, tx_mine_4);
  transaction tx_mine_5;
  construct_miner_tx(0, 0, 0, 0, 0, miner_acc5.get_keys().m_account_address, tx_mine_5);
  transaction tx_mine_6;
  construct_miner_tx(0, 0, 0, 0, 0, miner_acc6.get_keys().m_account_address, tx_mine_6);

  //fill inputs entry
  std::vector<tx_source_entry> sources;
  sources.resize(sources.size()+1);
  tx_source_entry& src = sources.back();
  src.amount = 70.44*1000000000000;
  {
    src.push_output(0, boost::get<txout_to_key>(tx_mine_1.vout[0].target).key, src.amount);

    src.push_output(1, boost::get<txout_to_key>(tx_mine_2.vout[0].target).key, src.amount);

    src.push_output(2, boost::get<txout_to_key>(tx_mine_3.vout[0].target).key, src.amount);

    src.push_output(3, boost::get<txout_to_key>(tx_mine_4.vout[0].target).key, src.amount);

    src.push_output(4, boost::get<txout_to_key>(tx_mine_5.vout[0].target).key, src.amount);

    src.push_output(5, boost::get<txout_to_key>(tx_mine_6.vout[0].target).key, src.amount);

    src.real_out_tx_key = cryptonote::get_tx_pub_key_from_extra(tx_mine_2);
    src.real_output = 1;
    src.rct = false;
    src.real_output_in_tx_index = 0;
  }

  //fill outputs entry
  std::vector<tx_destination_entry> destinations;

  account_base rv_acc1;
  rv_acc1.generate();

  memcpy((void *)rv_acc1.get_keys().m_account_address.m_spend_public_key.data, receiver_public_spend_key, 32);
  memcpy((void *)rv_acc1.get_keys().m_account_address.m_view_public_key.data, receiver_public_view_key, 32);

  tx_destination_entry td1;
  td1.addr = rv_acc1.get_keys().m_account_address;
  td1.amount = 69.36*1000000000000;
  destinations.push_back(td1);

  tx_destination_entry td_own;
  td_own.addr = miner_acc2.get_keys().m_account_address;
  td_own.amount = 0.55*1000000000000;
  destinations.push_back(td_own);

  transaction tx_rc1;
  std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
  subaddresses[miner_acc2.get_keys().m_account_address.m_spend_public_key] = {0,0};
  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;

  bool r = construct_tx_and_get_tx_key(miner_acc2.get_keys(), subaddresses, sources, destinations, miner_acc2.get_keys().m_account_address, std::vector<uint8_t>(), tx_rc1, tx_key, additional_tx_keys, true, { rct::RangeProofBulletproof, 0});

  CHECK_AND_ASSERT_MES(r, false, "failed to construct transaction");

  return true;
}

bool test_transactions_ledger()
{
  if(!test_transaction_generation_and_ring_signature_ledger())
    return false;

  return true;
}
