bundle_path = "../tls-ca-bundle.pem"

with open(bundle_path, 'r') as f:
    bundle = f.read()
    certs = bundle.split('\n\n')
    n = len(certs)
    for i in range(n):
        with open('%04d.pem'%(i+1), 'w') as cert_file:
            cert_file.write(certs[i])