//go:build !linux

package main

import "errors"

type admissionTime struct {
	BootID string
	NS     int64
}

func readAdmissionClock() (admissionTime, error) {
	return admissionTime{}, errors.New("helper admission v2 requires Linux CLOCK_BOOTTIME")
}

var admissionNow = readAdmissionClock

func validAdmissionLifetime(AdmissionReceipt, admissionTime) error {
	return errors.New("helper admission v2 requires Linux CLOCK_BOOTTIME")
}
