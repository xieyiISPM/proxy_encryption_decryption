import time
import pytest
from proxyEncrypt.proxy_encrypt_decrypt import ProxyEncryptionDecryption, SecurityHelper


@pytest.mark.skip
def test_encyption_decryption():
    proxy = ProxyEncryptionDecryption()
    alice = proxy.gen_key_pair()
    bob = proxy.gen_key_pair()
    alice_keys = proxy.gen_sender_keys()
    plain_text = b'GATCACAGGTCTATCACCCTATTAACCACTCACGGGAGCTCTCCATGCATTTGGTATTTTCGTCTGGGGGGTATGCACGCGATAGCATTGCGAGACGCTGGAGCCGGAGCACCCTATGTCGCAGTATCTGTCTTTGATTCCTGCCTCATCCCATTATTTATCGCACCTACGTTCAATATTACAGGCGAACATACTTACTAAAGTGTGTTAATTAATTAATGCTTGTAGGACATAATAATAACAATTGAATGTCTGCACAGCCGCTTTCCACACAGACATCATAACAAAAAATTTCCACCAAGCGCGTACACACCGCAATCTGGCCACAGCACTTAAACACATCTCTGCCAAACCCCAAAAACAAAGAACCCTAACACCAGCCTAACCAGATTTCAAATTTTATCTTTTGGCGGTATGCACTTTTAACAGTCACCCCCCAACTAACACATTATTTTCCCCTCCCACTCCCATACTACTAATCTCATCAATACAACCCCCGCCCATCCTACCCAGCACACACACACCGCTGCTAACCCCATACCCCGAACCAACCAAACCCCAAAGACACCCCCCACAGTTTATGTAGCTTACCTCCTCAAAGCAATACACTGAAAATGTTTAGACGGGCTCACATCACCCCATAAACAAATAGGTTTGGTCCTAGCCTTTCTATTAGCTCTTAGTAAGATTACACATGCAAGCATCCCCGTTCCAGTGAGTTCACCCTCTAAATCACCACGATCAAAAGGGACAAGCATCAAGCACGCAGCAATGCAGCTCAAAACGCTTAGCCTAGCCACACCCCCACGGGAAACAGCAGTGATTAACCTTTAGCAATAAACGAAAGTTTAACTAAGCTATACTAACCCCAGGGTTGGTCAATTTCGTGCCAGCCACCGCGGTCACACGATTAACCCAAGTCAATAGAAGCCGGCGTAAAGAGTGTTTTAGATCACCCCCTCCCCAATAAAGCTAAAACTCACCTGAGTTGTAAAAAACTCCAGTTGACACAAAATAGACTACGAAAGTGGCTTTAACATATCTGAACACACAATAGCTAAGACCCAAACTGGGATTAGATACCCCACTATGCTTAGCCCTAAACCTCAACAGTTAAATCAACAAAACTGCTCGCCAGAACACTACGAGCCACAGCTTAAAACTCAAAGGACCTGGCGGTGCTTCATATCCCTCTAGAGGAGCCTGTTCTGTAATCGATAAACCCCGATCAACCTCACCACCTCTTGCTCAGCCTATATACCGCCATCTTCAGCAAACCCTGATGAAGGCTACAAAGTAAGCGCAAGTACCCACGTAAAGACGTTAGGTCAAGGTGTAGCCCATGAGGTGGCAAGAAATGGGCTACATTTTCTACCCCAGAAAACTACGATAGCCCTTATGAAACTTAAGGGTCGAAGGTGGATTTAGCAGTAAACTGAGAGTAGAGTGCTTAGTTGAACAGGGCCCTGAAGCGCGTACACACCGCCCGTCACCCTCCTCAAGTATACTTCAAAGGACATTTAACTAAAACCCCTACGCATTTATATAGAGGAGACAAGTCGTAACATGGTAAGTGTACTGGAAAGTGCACTTGGACGAACCAGAGTGTAGCTTAACACAAAGCACCCAACTTACACTTAGGAGATTTCAACTTAACTTGACCGCTCTGAGCTAAACCTAGCCCCAAACCCACTCCACCTTACTACCAGACAACCTTAGCCAAACCATTTACCCAAATAAAGTATAGGCGATAGAAATTGAAACCTGGCGCAATAGATATAGTACCGCAAGGGAAAGATGAAAAATTATAACCAAGCATAATATAGCAAGGACTAACCCCTATACCTTCTGCATAATGAATTAACTAGAAATAACTTTGCAAGGAGAGCCAAAGCTAAGACCCCCGAAACCAGACGAGCTACCTAAGAACAGCTAAAAGAGCACACCCGTCTATGTAGCAAAATAGTGGGAAGATTTATAGGTAGAGGCGACAAACCTACCGAGCCTGGTGATAGCTGGTTGTCCAAGATAGAATCTTAGTTCAACTTTAAATTTGCCCACAGAACCCTCTAAATCCCCTTGTAAATTTAACTGTTAGTCCAAAGAGGAACAGCTCTTTGGACACTAGGAAAAAACCTTGTAGAGAGAGTAAAAAATTTAACACCCATAGTAGGCCTAAAAGCAGCCACCAATTAAGAAAGCGTTCAAGCTCAACACCCACTACCTAAAAAATCCCAAACATATAACTGAACTCCTCACACCCAATTGGACCAATCTATCACCCTATAGAAGAACTAATGTTAGTATAAGTAACATGAAAACATTCTCCTCCGCATAAGCCTGCGTCAGATTAAAACACTGAACTGACAATTAACAGCCCAATATCTACAATCAACCAACAAGTCATTATTACCCTCACTGTCAACCCAACACAGGCATGCTCATAAGGAAAGGTTAAAAAAAGTAAAAGGAACTCGGCAAATCTTACCCCGCCTGTTTACCAAAAACATCACCTCTAGCATCACCAGTATTAGAGGCACCGCCTGCCCAGTGACACATGTTTAACGGCCGCGGTACCCTAACCGTGCAAAGGTAGCATAATCACTTGTTCCTTAAATAGGGACCTGTATGAATGGCTCCACGAGGGTTCAGCTGTCTCTTACTTTTAACCAGTGAAATTGACCTGCCCGTGAAGAGGCGGGCATAACACAGCAAGACGAGAAGACCCTATGGAGCTTTAATTTATTAATGCAAACAGTACCTAACAAACCCACAGGTCCTAAACTACCAAACCTGCATTAAAAATTTCGGTTGGGGCGACCTCGGAGCAGAACCCAACCTCCGAGCAGTACATGCTAAGACTTCACCAGTCAAAGCGAACTACTATACTCAATTGATCCAATAACTTGACCAACGGAACAAGTTACCCTAGGGATAACAGCGCAATCCTATTCTAGAGTCCATATCAACAATAGGGTTTACGACCTCGATGTTGGATCA'
    start_time = time.clock()
    print('\nStart: ', start_time)
    encrypted_pair = proxy.encrypt_message(alice["public_key"], plain_text)
    kfrags = proxy.gen_key_fragments(alice['private_key'], bob['public_key'], alice_keys['signer'])
    cfrags = proxy.collect_c_frags(encrypted_pair['capsule'], kfrags)

    bob_decrypted_text = proxy.receiver_decrypt(bob['private_key'], alice['public_key'], encrypted_pair['capsule'],
                                                cfrags,
                                                encrypted_pair['ciphertext'])
    end_time = time.clock()
    print('Duration time: ', end_time - start_time)
    # print(bob_decrypted_text)
    assert bob_decrypted_text == plain_text


@pytest.mark.skip
def test_numbers_convert():
    helper = SecurityHelper()
    random_list = helper.gen_random_list(5, 10)
    byte_list = helper.convert_int_list_to_byte_list(random_list)
    converted_back = helper.convert_byte_list_to_int_list(byte_list)
    assert converted_back == random_list


@pytest.mark.skip
@pytest.mark.proxy_encryption_decrytion
def test_query_encryption_decryption():
    gen_sequence_length = 10
    proxy = ProxyEncryptionDecryption()
    querier = proxy.gen_key_pair()
    hospital = proxy.gen_key_pair()
    querier_keys = proxy.gen_sender_keys()
    helper = SecurityHelper()
    gen_sequence_hospital_part = helper.gen_random_list(int(gen_sequence_length), 10)
    gen_sequence_hospital_part_str = ','.join(gen_sequence_hospital_part)

    # print('Original half: ')
    # print(gen_sequence_hospital_part)

    before_test = time.clock()
    gen_sequence_hospital_part_byte = helper.convert_int_list_to_byte_list(gen_sequence_hospital_part)
    assert len(gen_sequence_hospital_part_byte) == int(gen_sequence_length)
    hospital_decrypted_gen_sequence_part_byte = list()
    for i in range(int(gen_sequence_length)):
        encrypted_pair = proxy.encrypt_message(querier["public_key"], gen_sequence_hospital_part_byte[i])
        kfrags = proxy.gen_key_fragments(querier['private_key'], hospital['public_key'], querier_keys['signer'])
        cfrags = proxy.collect_c_frags(encrypted_pair['capsule'], kfrags)

        hospital_decrypted_byte = proxy.receiver_decrypt(hospital['private_key'], querier['public_key'],
                                                         encrypted_pair['capsule'], cfrags,
                                                         encrypted_pair['ciphertext'])
        hospital_decrypted_gen_sequence_part_byte.append(hospital_decrypted_byte)
    hospital_decrypted_gen_sequence_part = helper.convert_byte_list_to_int_list(
        hospital_decrypted_gen_sequence_part_byte)

    after_test = time.clock()
    print('Test duration time : ', after_test - before_test)
    print(after_test)

    # print('decrypted half:')
    # print(hospital_decrypted_gen_sequence_part)
    assert hospital_decrypted_gen_sequence_part == gen_sequence_hospital_part


def test_query_encryption_decryption_optimal():
    gen_sequence_length = 3000
    proxy = ProxyEncryptionDecryption()
    querier = proxy.gen_key_pair()
    hospital = proxy.gen_key_pair()
    querier_keys = proxy.gen_sender_keys()
    helper = SecurityHelper()
    total_time = 0
    for i in range(10):
        gen_sequence_hospital_part_in_str = helper.gen_random_list_in_str(int(gen_sequence_length), 10)
        gen_sequence_hospital_part_in_num = helper.convert_str_list_to_int_list(gen_sequence_hospital_part_in_str)
        gen_sequence_hospital_part_str = ','.join(gen_sequence_hospital_part_in_str)
        # print('\noriginal gen-sequence: ', gen_sequence_hospital_part_in_num)

        before_test = time.clock()
        gen_sequence_hospital_part_byte = bytes(gen_sequence_hospital_part_str, 'utf-8')

        encrypted_pair = proxy.encrypt_message(querier["public_key"], gen_sequence_hospital_part_byte)
        kfrags = proxy.gen_key_fragments(querier['private_key'], hospital['public_key'], querier_keys['signer'])
        cfrags = proxy.collect_c_frags(encrypted_pair['capsule'], kfrags)

        hospital_decrypted_bytes = proxy.receiver_decrypt(hospital['private_key'], querier['public_key'],
                                                          encrypted_pair['capsule'], cfrags,
                                                          encrypted_pair['ciphertext'])

        hospital_decrypted_gen_sequence_part = (hospital_decrypted_bytes.decode('utf-8')).split(',')

        after_test = time.clock()
        total_time += after_test-before_test
        # print('\nTest duration time : ', after_test - before_test)
        hospital_decrypted_gen_sequence_part_in_num = helper.convert_str_list_to_int_list(
            hospital_decrypted_gen_sequence_part)

        # print('decrypted half:', hospital_decrypted_gen_sequence_part_in_num)
        # assert hospital_decrypted_gen_sequence_part_in_num == gen_sequence_hospital_part_in_num
    print('\nAverage time: ', total_time/10)

# Test result: Average time:  0.07985390000000002(s)