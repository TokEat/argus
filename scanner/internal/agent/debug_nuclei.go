package agent

func completeNucleiDebug(sendComplete func(string), err error) {
	if err != nil {
		sendComplete(err.Error())
		return
	}
	sendComplete("")
}
