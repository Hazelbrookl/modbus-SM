from gmssl import sm2, func

def generate_SM2_key():
    crypt = sm2.CryptSM2(private_key=None, public_key=None)
    private_key = func.random_hex(crypt.para_len)
    public_key = crypt._kg(int(private_key, 16), crypt.ecc_table['g'])

    return private_key, public_key

if __name__ == '__main__':
    private_key, public_key = generate_SM2_key()
    print('sm2_private_key:', private_key)
    print('sm2_public_key:', public_key)