//go:build !linux

package main

import "errors"

func readAdmissionFreeSpace(AdmissionConfig) (admissionFreeSpace, error) {
	return admissionFreeSpace{}, errors.New("helper admission v2 storage accounting requires Linux")
}

var admissionSpace = readAdmissionFreeSpace
