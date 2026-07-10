// Package challenge contains shared challenge-response constants.
package challenge

const ReasonPendingApproval = "pending recipient challenge-response approval"

func IsPendingReason(reason string) bool {
	return reason == ReasonPendingApproval
}
