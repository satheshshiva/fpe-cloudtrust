package format

type format struct {
	CharToInt    map[string]uint16
	IntToChar    map[uint16]string
	MinLength    int
	SkipOutliers bool
}

func NewGenericPIIFormat() *format {
	chars := " ~`@#$%^&*()!_-\":;'><,.?/[{]}+=\\|0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	m := make(map[string]uint16)
	n := make(map[uint16]string)
	//making the int to char and char to int maps
	for i, val := range chars {
		s := string(val)
		m[s] = uint16(i)
		n[uint16(i)] = s
	}
	return &format{
		CharToInt:    m,
		IntToChar:    n,
		MinLength:    4,
		SkipOutliers: true,
	}
}
