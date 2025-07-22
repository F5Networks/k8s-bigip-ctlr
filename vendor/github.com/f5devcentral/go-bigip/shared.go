package bigip

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

const (
	uriShared            = "shared"
	uriLicensing         = "licensing"
	uriActivation        = "activation"
	uriRegistration      = "registration"
	uriFileTransfer      = "file-transfer"
	uriUploads           = "uploads"
	activationComplete   = "LICENSING_COMPLETE"
	activationInProgress = "LICENSING_ACTIVATION_IN_PROGRESS"
	activationFailed     = "LICENSING_FAILED"
	activationNeedEula   = "NEED_EULA_ACCEPT"
)

// Installs the given license.
func (b *BigIP) InstallLicense(licenseText string) error {
	r := map[string]string{"licenseText": licenseText}
	return b.put(r, uriShared, uriLicensing, uriRegistration)
}

// Revoke license.
func (b *BigIP) RevokeLicense() error {
	//r := map[string]string{"licenseText": licenseText}
	return b.delete(uriShared, uriLicensing, uriRegistration)
}

// Upload a file
func (b *BigIP) UploadFile(f *os.File) (*Upload, error) {
	if strings.HasSuffix(f.Name(), ".iso") {
		err := fmt.Errorf("File must not have .iso extension")
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return b.Upload(f, info.Size(), uriShared, uriFileTransfer, uriUploads, info.Name())
}

// Upload a file from a byte slice
func (b *BigIP) UploadBytes(data []byte, filename string) (*Upload, error) {
	r := bytes.NewReader(data)
	size := int64(len(data))
	return b.Upload(r, size, uriShared, uriFileTransfer, uriUploads, filename)
}

// Upload a file from a byte slice
func (b *BigIP) UploadAsmBytes(data []byte, filename string) (*Upload, error) {
	r := bytes.NewReader(data)
	size := int64(len(data))
	return b.Upload(r, size, uriTm, uriAsm, uriFileTransfer, uriUploads, filename)
}
