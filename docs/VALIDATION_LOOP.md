# Validation Loop (Grade A)

This guide shows how to use cipdip’s Grade A validation to tighten packet builders.

## 1) Emit bytes from catalog operations

```powershell
.\cipdip.exe emit-bytes --catalog-root workspaces\workspace --catalog-key identity.vendor_id --output reports\emit.json
```

To emit all catalog entries:

```powershell
.\cipdip.exe emit-bytes --catalog-root workspaces\workspace --all --output reports\emit.json
```

## 2) Validate emitted bytes (Grade A)

```powershell
.\cipdip.exe validate-bytes --input reports\emit.json --profile client_wire --verbose --report-json reports\validation_report.json
```

- `client_wire` validates request packets without requiring responses.
- `server_wire` validates response packets and requires status fields.
- `pairing` focuses on request/response correlation (not required for Grade A).

## 3) Use Grade A failures to fix builders

Each packet includes `grade` and `failure_labels` in the JSON report. Example labels:

- `INV_ENIP_LENGTH_MISMATCH`
- `INV_CPF_ITEMCOUNT_IMPLAUSIBLE`
- `INV_CIP_PATHSIZE_MISMATCH`
- `INV_CIP_PATH_MISSING`
- `INV_CIP_SERVICE_DATA_SHAPE_MISMATCH`
- `TSHARK_MALFORMED`

Use these to identify where encoding is incorrect, update the builder, and re-run validation.

## 4) Validate PCAP fixtures (optional)

```powershell
.\cipdip.exe pcap-validate --generate-test-pcaps --output pcaps\validation_generated --profile client_wire --verbose
```
