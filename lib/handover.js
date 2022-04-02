/*!
 * handover.js - External-network resolver plugin for hsd
 * Copyright (c) 2021 Matthew Zipkin (MIT License).
 */

'use strict';

const {wire, util} = require('bns');
const {BufferReader} = require('bufio');
const Ethereum = require('./ethereum');

const TYPE_MAP_EMPTY = Buffer.from('0006000000000003', 'hex');
const TYPE_MAP_ALL = [
  wire.types.A, wire.types.HINFO, wire.types.MX,
  wire.types.TXT, wire.types.AAAA, wire.types.LOC, wire.types.SRV,
  wire.types.NAPTR, wire.types.CERT, wire.types.SSHFP, wire.types.RRSIG,
  wire.types.NSEC, wire.types.DNSKEY, wire.types.TLSA, wire.types.SMIMEA,
  wire.types.HIP, wire.types.CDS, wire.types.CDNSKEY, wire.types.OPENPGPKEY,
  wire.types.SPF, wire.types.URI, wire.types.CAA
];

const plugin = exports;

class Plugin {
  constructor(node) {
    this.ready = false;
    this.node = node;
    this.ns = node.ns;
    this.logger = node.logger.context('handover');

    this.ethereum = new Ethereum({
      projectId: node.config.str('handover-infura-projectid'),
      projectSecret: node.config.str('handover-infura-projectsecret')
    });

    // Plugin can not operate if root server isn't enabled
    if (!this.ns)
      return;

    // Middleware function that intercepts queries to root
    // before cache, blocklist or HNS lookup
    this.ns.middle = async (tld, req) => {
      // To avoid poisoning recursive cache
      // wait until plugin is ready
      if (!this.ready) {
        const res = new wire.Message();
        res.code = wire.codes.REFUSED;
        return res;
      }
      
      // important not lowercased by hsd
      tld = tld.toLowerCase();
      
      const [qs] = req.question;
      const name = qs.name.toLowerCase();
      const type = qs.type;
      const labels = util.split(name);

      // The plugin can resolve direct queries for ENS (.eth) names,
      // but we must get the complete query string from the recursive resolver.
      // That way we don't need to run a separate authoritative nameserver.
      // If the recursive is "minimizing query names" and only requesting a
      // referral for the TLD, we claim authority so it sends us the full name.
      let data;
      switch (tld) {
        case 'eth.':
          if (labels.length < 2) {
            return this.sendSOA(name, tld, type);
          }

          try {
            data = await this.ethereum.resolveDnsFromEns(name, type);
            if (data && data.length > 0)
              return this.sendData(data, type);
          } catch (e) {
            this.logger.warning('Resolution failed for name: %s', name);
            this.logger.debug(e.stack);
          }

          return this.sendSOA(name, tld, type);
        case '_eth.':
          return this.sendSOA(name, tld, type);
      }

      // Next, try actually resolving the name with the HNS root zone.
      // We are going to examine the result before sending it back.
      const originalRes = await this.resolveHNS(req, name, type, tld);
      let res = null;

      // Special DS processing if the request is "<hip-5 tld> DS"
      // handover won't find any referral in the answer
      // it won't recognize it as a HIP5 name which results 
      // in a bad proof "NS RRSIG NSEC". Need to manually
      // request "<hip-5 tld> NS" for handover to process it.
      if (type === wire.types.DS && labels.length === 1) {
          res = await this.resolveHNS({
            question: [
              new wire.Question(name, wire.types.NS)
            ]
          }, name, wire.types.NS, tld);
      } else {
          res = originalRes;
      }

      // If there's no NS records, we're done, plugin is bypassed.
      if (!res.authority.length)
        return res;

      let hip5Referral = false;
      // Check NS records for HIP-5 referrals
      for (const rr of res.authority) {
        if (rr.type !== wire.types.NS)
          continue;

        const ending = util.label(rr.data.ns, util.split(rr.data.ns), -1);

        // Look for any supported HIP-5 extension in the NS record
        // and query it for the user's original request.
        if (ending === '_eth' || ending === 'eth') {
          hip5Referral = true;

          // If the recursive is being minimal, don't look up the name.
          // Send the SOA back and get the full query from the recursive .
          if (labels.length < 2) {
            return this.sendSOA(name, tld, type);
          }
          this.logger.debug(
            'Intercepted referral to .%s: %s %s -> %s NS: %s',
            ending,
            name,
            wire.typesByVal[type],
            rr.name,
            rr.data.ns
          );

          try {
            switch (ending) {
              case 'eth':
                data = await this.ethereum.resolveDnsFromEns(
                  name,
                  type,
                  rr.data.ns
                );
                break;
              case '_eth':
                // Look up an alternate (forked) ENS contract by the Ethereum
                // address specified in the NS record
                data = await this.ethereum.resolveDnsFromAbstractEns(
                  name,
                  type,
                  rr.data.ns
                );
                break;
            }
          } catch (e) {
            this.logger.warning('Resolution failed for name: %s', name);
            this.logger.debug(e.stack);
          }
        }
      }

      if (!data || data.length === 0) {
        // Never send HIP-5 type referrals to recursive resolvers
        // since they aren't real delegations and it could end up
        // poisoning their cache.
        if (hip5Referral) {
          return this.sendSOA(name, tld, type);
        }

        // return the HNS root server response unmodified.
        return originalRes;
      }

      // If we did get an answer, mark the response
      // as authoritative and send the new answer.
      this.logger.debug('Returning answers from alternate naming system');
      return this.sendData(data, type);
    };
  }

  async open() {
    this.logger.info('handover external network resolver plugin installed.');

    // The first thing this plugin wants to do when it's opened is
    // contact https://mainnet.infura.io/. Of course, if this instance
    // of hsd is being used to resolve DNS for the system it is running on,
    // that is not yet possible at this point in the hsd life cycle!
    // The best we can do is wait for the node to fully sync so
    // we can properly resolve names.
    if (this.node.chain.isFull()) {
      await this.ethereum.init();
      this.ready = true;
      this.logger.info(
        'handover external network resolver plugin is active!'
      );
    }

    this.node.chain.on('full', async () => {
      await this.ethereum.init();
      this.ready = true;
      this.logger.info(
        'handover external network resolver plugin is active!'
      );
    });
  }

  close() {
    this.ready = false;
  }

  // Copy hsd's server.resolve() to lookup a name on HNS normally
  async resolveHNS(req, name, type, tld) {
    let res = null;
    // Check the root resolver cache first
    const cache = this.ns.cache.get(name, type);

    if (cache) {
      res = cache;
    } else {
      res = await this.ns.response(req);
      // Cache responses
      if (!util.equal(tld, '_synth.'))
        this.ns.cache.set(name, type, res);
    }
    return res;
  }

  //  send SOA-only when we don't have / don't want to answer.
  async sendSOA(name, tld, type) {
    const res = new wire.Message();
    res.aa = true;
    const nsec = this.toNSEC(name);

    if (name === tld) {
      // Prove ENT with NSEC RRSIG
      nsec.data.typeBitmap = TYPE_MAP_EMPTY;
    } else {
      // claim all types exist except for qtype
      const typeMap = TYPE_MAP_ALL.filter((v) => {
        return v !== type;
      });

      nsec.data.setTypes(typeMap);
    }

    res.authority.push(nsec);
    this.ns.signRRSet(res.authority, wire.types.NSEC);
    res.authority.push(this.ns.toSOA());
    this.ns.signRRSet(res.authority, wire.types.SOA);

    return res;
  }

  toNSEC(name) {
    const rr = new wire.Record();
    const rd = new wire.NSECRecord();
    rr.name = util.fqdn(name);
    rr.type = wire.types.NSEC;
    rr.ttl = 36 * 10 * 60;

    rd.nextDomain = util.fqdn("\\000." + name);
    rr.data = rd;

    return rr;
  }

  // Convert a wire-format DNS record to a message and send.
  sendData(data, type) {
    const res = new wire.Message();
    res.aa = true;
    const br = new BufferReader(data);
    while (br.left() > 0) {
      const rr = wire.Record.read(br);
      if (rr.type === wire.types.NS)
        res.authority.push(rr);
      else if (rr.type === type || rr.type === wire.types.CNAME)
        res.answer.push(rr);
      else
        res.authority.push(rr);
    }

    // Referral answer
    if (res.answer.length === 0 && res.authority.length > 0) {
      res.aa = false;
      this.ns.signRRSet(res.authority, wire.types.DS);
    }

    // Answers resolved from alternate name systems appear to come directly
    // from the HNS root zone.
    this.ns.signRRSet(res.answer, type);

    if (type !== wire.types.CNAME)
      this.ns.signRRSet(res.answer, wire.types.CNAME);

    return res;
  }
}

plugin.id = 'handover';
plugin.init = function init(node) {
  return new Plugin(node);
};
