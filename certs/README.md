# Certificados TLS

Esta carpeta debe contener los certificados para conectar con Consul via HTTPS.

## Archivos necesarios

```
certs/
└── ca.pem          # Certificado de la CA (Certificate Authority)
```

## Notas

- El chassis usa `verify=False` en las conexiones HTTPS a Consul, por lo que el certificado CA es opcional.
- Si quieres habilitar verificación completa, configura `CONSUL_VERIFY=true` y asegúrate de que `ca.pem` sea válido.
- Puedes copiar el certificado desde otra instancia o generarlo con los mismos que usa tu infraestructura.

## Copiar desde Order

Si tienes los certificados en el servicio Order:

```bash
# Desde la máquina que tiene los certs
cp /path/to/certs/ca.pem ./certs/
```

## Generar certificado autofirmado (solo para desarrollo)

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ca-key.pem \
    -out ca.pem \
    -subj "/CN=ADS-CA"
```
