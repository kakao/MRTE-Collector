package mrte

import (

)

func ConvertUint32ToBytesLE(val uint32) (rtn []byte){
	p1 := make([]byte, 4)
	p1[3] = byte(val >> 24 & 0xFF)	
	p1[2] = byte(val >> 16 & 0xFF)
	p1[1] = byte(val >> 8 & 0xFF)
	p1[0] = byte(val & 0xFF)
		
	return p1
}

func ConvertUint32ToBytesBE(val uint32) (rtn []byte){
	p1 := make([]byte, 4)
	p1[0] = byte(val >> 24 & 0xFF)	
	p1[1] = byte(val >> 16 & 0xFF)
	p1[2] = byte(val >> 8 & 0xFF)
	p1[3] = byte(val & 0xFF)
		
	return p1
}

func ConvertUint24ToBytesLE(val uint32) (rtn []byte){
	p1 := make([]byte, 3)
	p1[2] = (byte)(val >> 16 & 0xFF)
	p1[1] = (byte)(val >> 8 & 0xFF)
	p1[0] = (byte)(val & 0xFF)
	
	return p1
}

func ConvertUint24ToBytesBE(val uint32) (rtn []byte){
	p1 := make([]byte, 3)
	p1[0] = (byte)(val >> 16 & 0xFF)
	p1[1] = (byte)(val >> 8 & 0xFF)
	p1[2] = (byte)(val & 0xFF)
	
	return p1
}

func ConvertUint16ToBytesLE(val uint16) (rtn []byte){
	p1 := make([]byte, 2)
	p1[1] = byte(val >> 8 & 0xFF)
	p1[0] = byte(val & 0xFF)
	
	return p1
}

func ConvertUint16ToBytesBE(val uint16) (rtn []byte){
	p1 := make([]byte, 2)
	p1[0] = byte(val >> 8 & 0xFF)
	p1[1] = byte(val & 0xFF)
	
	return p1
}