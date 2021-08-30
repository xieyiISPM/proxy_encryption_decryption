from umbral import SecretKey, Signer
from umbral import encrypt, decrypt_original, generate_kfrags
from umbral import pre
import random


# Generate Umbral keys
class ProxyEncryptionDecryption:

    def gen_key_pair(self):
        user_secret_key = SecretKey.random()
        user_public_key = user_secret_key.public_key()
        key_pair = {"public_key": user_public_key, "private_key": user_secret_key}
        return key_pair

    def gen_sender_keys(self):
        sender_signing_key = SecretKey.random()
        sender_signer = Signer(sender_signing_key)
        sender_verifying_key = sender_signing_key.public_key()
        sender_keys = {"signer": sender_signer, "verifier": sender_verifying_key}
        return sender_keys

    def encrypt_message(self, sender_public_key, message):
        capsule, ciphertext = encrypt(sender_public_key, message)
        return {"capsule": capsule, "ciphertext": ciphertext}

    def decrypt_message(self, sender_private_key, capsule, ciphertext):
        return decrypt_original(sender_private_key, capsule, ciphertext)

    def gen_key_fragments(self, sender_private_key, receiver_public_key, signer):
        return generate_kfrags(delegating_sk=sender_private_key, receiving_pk=receiver_public_key, signer=signer,
                               threshold=10, num_kfrags=20)

    def collect_c_frags(self, capsule, kfrags):
        cfrags = []
        for kfrag in kfrags[:10]:
            cfrag = pre.reencrypt(capsule=capsule, kfrag=kfrag)
            cfrags.append(cfrag)
        return cfrags

    def receiver_decrypt(self, receiver_private_key, sender_public_key, capsule, cfrags, ciphertext):
        return pre.decrypt_reencrypted(receiving_sk=receiver_private_key, delegating_pk=sender_public_key,
                                       capsule=capsule, verified_cfrags=cfrags, ciphertext=ciphertext)


class SecurityHelper:

    def gen_random_list(self, list_size, bit_size):
        random_list = list()
        for i in range(list_size):
            random_list.append(random.getrandbits(bit_size))
        return random_list

    def gen_random_list_in_str(self, list_size, bit_size):
        random_list = list()
        for i in range(list_size):
            random_list.append(str(random.getrandbits(bit_size)))
        return random_list

    def convert_int_list_to_byte_list(self, int_list, length_array=10 ):
        byte_list = list()
        for item in int_list:
            byte_list.append(item.to_bytes(length_array, 'little'))
        return byte_list

    def convert_byte_list_to_int_list(self, bytes_list):
        int_list = list()
        for item in bytes_list:
            int_list.append(int.from_bytes(item, 'little'))
        return int_list

    def convert_str_list_to_int_list(self, str_list):
        int_list = list()
        for item in str_list:
            int_list.append(int(item))
        return int_list



