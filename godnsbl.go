package dnsbl

import (
	"errors"
	"fmt"
	"net"
)

var ErrUnknown = errors.New("Unknown bl error")

type DnsBL struct {
}

type Result struct {
	Code  string
	Texts []string
}

type Blacklist string

var (
	BlacklistAbuseAt            = Blacklist("%d.%d.%d.%d.cbl.abuseat.org")
	BlacklistAbuseCh            = Blacklist("%d.%d.%d.%d.combined.abuse.ch")
	BlacklistAbuseChSpam        = Blacklist("%d.%d.%d.%d.spam.abuse.ch")
	BlacklistAntiSpam           = Blacklist("%d.%d.%d.%d.cdl.anti-spam.org.cn")
	BlacklistAupads             = Blacklist("%d.%d.%d.%d.duinv.aupads.org")
	BlacklistAupadsOrveDb       = Blacklist("%d.%d.%d.%d.orvedb.aupads.org")
	BlacklistBackScatterer      = Blacklist("%d.%d.%d.%d.ips.backscatterer.org")
	BlacklistBarracudaCentral   = Blacklist("%d.%d.%d.%d.b.barracudacentral.org")
	BlacklistBit                = Blacklist("%d.%d.%d.%d.virbl.bit.nl")
	BlacklistCyberlogic         = Blacklist("%d.%d.%d.%d.dnsbl.cyberlogic.net")
	BlacklistCymru              = Blacklist("%d.%d.%d.%d.bogons.cymru.com")
	BlacklistDroneAbuseCh       = Blacklist("%d.%d.%d.%d.drone.abuse.ch")
	BlacklistDul                = Blacklist("%d.%d.%d.%d.dul.ru")
	BlacklistEmailBasura        = Blacklist("%d.%d.%d.%d.bl.emailbasura.org")
	BlacklistFiveTenSG          = Blacklist("%d.%d.%d.%d.blackholes.five-ten-sg.com")
	BlacklistGweepProxy         = Blacklist("%d.%d.%d.%d.proxy.bl.gweep.ca")
	BlacklistGweepRelays        = Blacklist("%d.%d.%d.%d.relays.bl.gweep.ca")
	BlacklistImpWormRbl         = Blacklist("%d.%d.%d.%d.wormrbl.imp.ch")
	BlacklistInps               = Blacklist("%d.%d.%d.%d.dnsbl.inps.de")
	BlacklistInterServer        = Blacklist("%d.%d.%d.%d.rbl.interserver.net")
	BlacklistKoreaServices      = Blacklist("%d.%d.%d.%d.korea.services.net")
	BlacklistKundenserverRelays = Blacklist("%d.%d.%d.%d.relays.bl.kundenserver.de")
	BlacklistLashback           = Blacklist("%d.%d.%d.%d.ubl.lashback.com")
	BlacklistManitu             = Blacklist("%d.%d.%d.%d.ix.dnsbl.manitu.net")
	BlacklistMegaRbl            = Blacklist("%d.%d.%d.%d.rbl.megarbl.net")
	BlacklistMsrblCombined      = Blacklist("%d.%d.%d.%d.combined.rbl.msrbl.net")
	BlacklistMsrblImages        = Blacklist("%d.%d.%d.%d.images.rbl.msrbl.net")
	BlacklistMsrblPhishing      = Blacklist("%d.%d.%d.%d.phishing.rbl.msrbl.net")
	BlacklistMsrblSpam          = Blacklist("%d.%d.%d.%d.spam.rbl.msrbl.net")
	BlacklistMsrblVirus         = Blacklist("%d.%d.%d.%d.virus.rbl.msrbl.net")
	BlacklistNetherRelays       = Blacklist("%d.%d.%d.%d.relays.nether.net")
	BlacklistRblShort           = Blacklist("%d.%d.%d.%d.short.rbl.jp")
	BlacklistRblVirus           = Blacklist("%d.%d.%d.%d.virus.rbl.jp")
	BlacklistRothen             = Blacklist("%d.%d.%d.%d.dynip.rothen.com")
	BlacklistSectoorTor         = Blacklist("%d.%d.%d.%d.tor.dnsbl.sectoor.de")
	BlacklistSectoorTorserver   = Blacklist("%d.%d.%d.%d.torserver.tor.dnsbl.sectoor.de")
	BlacklistSorbenHttp         = Blacklist("%d.%d.%d.%d.http.dnsbl.sorbs.net")
	BlacklistSorbs              = Blacklist("%d.%d.%d.%d.dnsbl.sorbs.net")
	BlacklistSorbsDul           = Blacklist("%d.%d.%d.%d.dul.dnsbl.sorbs.net")
	BlacklistSorbsMisc          = Blacklist("%d.%d.%d.%d.misc.dnsbl.sorbs.net")
	BlacklistSorbsSmtp          = Blacklist("%d.%d.%d.%d.smtp.dnsbl.sorbs.net")
	BlacklistSorbsSocks         = Blacklist("%d.%d.%d.%d.socks.dnsbl.sorbs.net")
	BlacklistSorbsSpam          = Blacklist("%d.%d.%d.%d.spam.dnsbl.sorbs.net")
	BlacklistSorbsWeb           = Blacklist("%d.%d.%d.%d.web.dnsbl.sorbs.net")
	BlacklistSorbsZombie        = Blacklist("%d.%d.%d.%d.zombie.dnsbl.sorbs.net")
	BlacklistSpamCannibal       = Blacklist("%d.%d.%d.%d.bl.spamcannibal.org")
	BlacklistSpamCop            = Blacklist("%d.%d.%d.%d.bl.spamcop.net")
	BlacklistSpamRbl            = Blacklist("%d.%d.%d.%d.spamrbl.imp.ch")
	BlacklistSpamhausSbl        = Blacklist("%d.%d.%d.%d.sbl.spamhaus.org")
	BlacklistSpamhausPbl        = Blacklist("%d.%d.%d.%d.pbl.spamhaus.org")
	BlacklistSpamhausXbl        = Blacklist("%d.%d.%d.%d.xbl.spamhaus.org")
	BlacklistSpamhausZen        = Blacklist("%d.%d.%d.%d.zen.spamhaus.org")
	BlacklistSpamlist           = Blacklist("%d.%d.%d.%d.spamlist.or.kr")
	BlacklistSpamratsDyna       = Blacklist("%d.%d.%d.%d.dyna.spamrats.com")
	BlacklistSpamratsNoPtr      = Blacklist("%d.%d.%d.%d.noptr.spamrats.com")
	BlacklistSpamratsSpam       = Blacklist("%d.%d.%d.%d.spam.spamrats.com")
	BlacklistSurrielPsbl        = Blacklist("%d.%d.%d.%d.psbl.surriel.com")
	BlacklistTransipProxy       = Blacklist("%d.%d.%d.%d.proxy.block.transip.nl")
	BlacklistTransipResidential = Blacklist("%d.%d.%d.%d.residential.block.transip.nl")
	BlacklistUceProtect         = Blacklist("%d.%d.%d.%d.dnsbl-1.uceprotect.net")
	BlacklistUceProtect1        = Blacklist("%d.%d.%d.%d.dnsbl-1.uceprotect.net")
	BlacklistUceProtect2        = Blacklist("%d.%d.%d.%d.dnsbl-2.uceprotect.net")
	BlacklistUceProtect3        = Blacklist("%d.%d.%d.%d.dnsbl-3.uceprotect.net")
	BlacklistUnsubscore         = Blacklist("%d.%d.%d.%d.ubl.unsubscore.com")
	BlacklistWbpl               = Blacklist("%d.%d.%d.%d.db.wpbl.info")
	BlacklistWoodyCh            = Blacklist("%d.%d.%d.%d.blacklist.woody.ch")
)

func Check(bl Blacklist, ip net.IP) (*Result, error) {
	host := fmt.Sprintf(string(bl), ip[15], ip[14], ip[13], ip[12])

	var ips []net.IP
	var err error

	if ips, err = net.LookupIP(host); err != nil {
		switch v := err.(type) {
		case *net.DNSError:
			if v.Err == "no such host" {
				return nil, nil
			}
		}

		return nil, err
	}

	if len(ips) == 0 {
		return nil, nil
	}

	result := &Result{Code: ips[0].String()}

	// retrieve additional information from text records
	if result.Texts, err = net.LookupTXT(host); err != nil {
		// no additional information available
		// ignore
	}

	if ips[0][12] != 127 {
		return nil, ErrUnknown
	}

	return result, nil
}
