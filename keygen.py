from encrypt import generate_rsa_keypair, save_public_key, save_private_key

priv, pub = generate_rsa_keypair()

save_private_key(priv, "private.pem")
save_public_key(pub, "public.pem")

print("Keys generated: private.pem & public.pem")
