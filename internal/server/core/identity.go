package core

func (s *Server) identityValues() (uint16, uint16, uint16, uint8, uint8, uint16, uint32, string) {
	cfg := s.config.Server
	vendorID := cfg.IdentityVendorID
	deviceType := cfg.IdentityDeviceType
	productCode := cfg.IdentityProductCode
	revMajor := cfg.IdentityRevMajor
	revMinor := cfg.IdentityRevMinor
	status := cfg.IdentityStatus
	serial := cfg.IdentitySerial
	productName := cfg.IdentityProductName
	if productName == "" {
		if cfg.Name != "" {
			productName = cfg.Name
		} else {
			productName = "CIPDIP"
		}
	}
	if revMajor == 0 && revMinor == 0 {
		revMajor = 1
	}
	return vendorID, deviceType, productCode, revMajor, revMinor, status, serial, productName
}
