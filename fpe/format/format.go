package format

type Fpeformat struct {
	CharToInt    map[string]uint16
	IntToChar    map[uint16]string
	MinLength    int
	SkipOutliers bool
}

func NewGenericPIIFormat() *Fpeformat {
	chars := " ~`@#$%^&*()!_-\":;'><,.?/[{]}+=\\|0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	m := make(map[string]uint16)
	n := make(map[uint16]string)
	//making the int to char and char to int maps
	initMaps(chars, m, n)
	return &Fpeformat{
		CharToInt:    m,
		IntToChar:    n,
		MinLength:    4,
		SkipOutliers: false,
	}
}

func initMaps(chars string, m map[string]uint16, n map[uint16]string) {
	for i, val := range chars {
		s := string(val)
		m[s] = uint16(i)
		n[uint16(i)] = s
	}
}

func NewPANFullFpe() *Fpeformat {
	chars := "0123456789"
	m := make(map[string]uint16)
	n := make(map[uint16]string)
	//making the int to char and char to int maps
	initMaps(chars, m, n)
	return &Fpeformat{
		CharToInt:    m,
		IntToChar:    n,
		MinLength:    11,
		SkipOutliers: true,
	}
}

func NewSSNFullFpe() *Fpeformat {
	chars := "0123456789"
	m := make(map[string]uint16)
	n := make(map[uint16]string)
	//making the int to char and char to int maps
	initMaps(chars, m, n)
	return &Fpeformat{
		CharToInt:    m,
		IntToChar:    n,
		MinLength:    9,
		SkipOutliers: true,
	}
}
