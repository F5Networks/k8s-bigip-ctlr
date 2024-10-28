package clustermanager

type AdminState string

const (
	Disable AdminState = "disable"
	Enable  AdminState = "enable"
	Offline AdminState = "offline"
	NoPool  AdminState = "no-pool"
)
