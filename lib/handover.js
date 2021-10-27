/*!
 * handover.js - External-network resolver plugin for hsd
 * Copyright (c) 2021 Matthew Zipkin (MIT License).
 */

'use strict';

const {wire, util} = require('bns');
const {BufferReader} = require('bufio');
const Ethereum = require('./ethereum');
const {Record} = require("bns");

const plugin = exports;
const TYPE_MAP_EMPTY =  Buffer.from('0006000000000003', 'hex');

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

    // Plugin can not operate if node doesn't have root server
    if (!this.ns)
      return;

    // Middleware function that intercepts queries to root
    // before cache, blocklist or HNS lookup
    this.ns.middle = async (tld, req) => {
      if (!this.ready)
        return null;

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
            return this.sendSOA(tld, name, type);
          } else {
            data = await this.ethereum.resolveDnsFromEns(name, type);
            if (!data || data.length === 0)
              return this.sendSOA(name, type, labels);

            return this.sendData(data, type);
          }
        case '_eth.':
          return this.sendSOA(name, type, labels);
      }

      // Next, try actually resolving the name with the HNS root zone.
      // We are going to examine the result before sending it back.
      let stype = type;

      // special handling for DS
      if (labels.length === 1 && type === wire.types.DS)
        stype = wire.types.NS;

      const res = await this.resolveHNS(req, name, stype, tld);

      // If there's no NS records, we're done, plugin is bypassed.
      if (!res.authority.length)
        return res;

      let hasEnsReferral = false;
      // Check NS records for referals to TLDs `.eth` and `._eth`
      for (const rr of res.authority) {
        if (rr.type !== wire.types.NS)
          continue;

        // Look up the ENS resolver specified in the NS record
        // and query it for the user's original request
        if (rr.data.ns.slice(-5) === '.eth.') {
          hasEnsReferral = true;

          // If the recursive is being minimal, don't look up the name.
          // Send the SOA back and get the full query from the recursive .
          if (labels.length < 2) {
            return this.sendSOA(name, type, labels);
          }

          this.logger.debug(
            'Intercepted referral to .eth: %s %s -> NS: %s',
            name,
            wire.typesByVal[type],
            rr.data.ns
          );
          data = await this.ethereum.resolveDnsFromEns(
            name,
            type,
            rr.data.ns
          );
        }

        // Look up an alternate (forked) ENS contract by the Ethereum
        // address specified in the NS record, and query it for
        // the user's original request
        if (rr.data.ns.slice(-6) === '._eth.') {
          hasEnsReferral = true;

          // If the recursive is being minimal, don't look up the name.
          // Send the SOA back and get the full query from the recursive .
          if (labels.length < 2) {
            return this.sendSOA(name, type, labels);
          }
          this.logger.debug(
            'Intercepted referral to ._eth: %s %s -> %s NS: %s',
            name,
            wire.typesByVal[type],
            rr.name,
            rr.data.ns
          );
          data = await this.ethereum.resolveDnsFromAbstractEns(
            name,
            type,
            rr.data.ns
          );
        }
      }

      // If the Ethereum stuff came up empty, return the
      // HNS root server response unmodified.
      if (!data || data.length === 0) {
        // never send referrals that end with .eth or ._eth
        // since recursive may cache these referrals causing a servfail
        // for future lookups
        if (hasEnsReferral) {
          return this.sendSOA(name, type, labels);
        }

        // if we looked up a different type
        // query again with original qtype
        if (stype !== type)
          return await this.resolveHNS(req, name, type, tld);

        return res;
      }

      // If we did get an answer from Ethereum, mark the response
      // as authoritative and send the new answer.
      this.logger.debug('Returning answers from alternate naming system');
      return this.sendData(data, type);
    };
  }

  async open() {
    this.logger.info('handover external network resolver plugin installed.');

    if (!this.node.rs) {
      await this.ethereum.init();
      this.ready = true;
      this.logger.info(
        'handover external network resolver plugin is active!'
      );
    } else {
      // The first thing this plugin wants to do when it's opened is
      // contact https://mainnet.infura.io/. Of course, if this instance
      // of hsd is being used to resolve DNS for the system it is running on,
      // that is not yet possible at this point in the hsd life cycle!
      // The best we can do is wait for this event from the recursive resolver,
      // and even then we still need to give it another second before we
      // can resolve DNS with... ourself.
      this.node.rs.on('listening', async () => {
        await new Promise(r => setTimeout(r, 1000));
        await this.ethereum.init();
        this.ready = true;
        this.logger.info(
          'handover external network resolver plugin is active!'
        );
      });
    }
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
  async sendSOA(name, type, labels) {
    const res = new wire.Message();
    res.aa = true;
    res.authority.push(this.ns.toSOA());
    this.ns.signRRSet(res.authority, wire.types.SOA);
    this.logger.error("looking up ", name)

    if (labels.length === 1) {
      const rr = new wire.Record();
      const rd = new wire.NSECRecord();
      rr.name = util.fqdn(name);
      rr.type = wire.types.NSEC;
      rr.ttl = 60 * 60 * 60;

      rd.nextDomain = util.fqdn("\\000." + name);
      rd.typeBitmap = TYPE_MAP_EMPTY;
      rr.data = rd;

      res.authority.push(rr);
      this.ns.signRRSet(res.authority, wire.types.NSEC);
      return res;
    }

    const rr = new wire.Record();
    const rd = new wire.NSECRecord();
    rr.name = util.fqdn(name);
    rr.type = wire.types.NSEC;
    rr.ttl = 60 * 60 * 60;

    rd.nextDomain = util.fqdn("\\000." + name);

    const types = [wire.types.A, wire.types.NS, wire.types.SOA, wire.types.HINFO, wire.types.MX,
      wire.types.TXT, wire.types.AAAA, wire.types.LOC, wire.types.SRV, wire.types.NAPTR,
      wire.types.CERT, wire.types.SSHFP, wire.types.RRSIG, wire.types.NSEC,
      wire.types.DNSKEY, wire.types.TLSA, wire.types.SMIMEA, wire.types.HIP, wire.types.CDS,
      wire.types.CDNSKEY, wire.types.OPENPGPKEY, wire.types.SPF, wire.types.URI, wire.types.CAA];

    const idx = types.indexOf(type);
    if (idx === -1) {
      rd.setTypes(types)
    } else {
      types.splice(idx, 1)
      rd.setTypes(types);
    }

    rr.data = rd;

    res.authority.push(rr);
    this.ns.signRRSet(res.authority, wire.types.NSEC);
    return res;
  }

  // Convert a wire-format DNS record to a message and send.
  sendData(data, type) {
    const res = new wire.Message();
    res.aa = true;
    const br = new BufferReader(data);
    while (br.left() > 0) {
      const rr = wire.Record.read(br);
      if (rr.type !== type && rr.type !== wire.types.CNAME)
        res.authority.push(rr);
      else if (type === wire.types.NS && rr.type === type)
        res.authority.push(rr);
      else if (type === wire.types.NS && rr.type === wire.types.DS)
        res.authority.push(rr);
      else
        res.answer.push(rr);
    }

    if (res.answer.length === 0 && res.authority.length > 0)
      res.aa = false;

    // Answers resolved from alternate name systems appear to come directly
    // from the HNS root zone.
    this.ns.signRRSet(res.answer, type);

    if (type !== wire.types.CNAME)
      this.ns.signRRSet(res.answer, wire.types.CNAME);

    if (type !== wire.types.DS)
      this.ns.signRRSet(res.authority, wire.types.DS);

    return res;
  }
}

plugin.id = 'handover';
plugin.init = function init(node) {
  return new Plugin(node);
};
