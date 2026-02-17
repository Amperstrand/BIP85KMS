import { describe, it, expect } from 'vitest';
import { 
  jcs, 
  semanticToIndex, 
  deriveFromSemanticPath,
  deriveMasterNodeFromMnemonic,
  validateSemanticSegment
} from '../src/bip85kms';

const TEST_MNEMONIC = 'bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon';

describe('JSON Canonicalization Scheme (JCS)', () => {
  it('canonicalizes simple objects', () => {
    const obj = { b: 1, a: 2 };
    expect(jcs(obj)).toBe('{"a":2,"b":1}');
  });

  it('produces same output regardless of key order', () => {
    const obj1 = { z: 3, a: 1, m: 2 };
    const obj2 = { a: 1, m: 2, z: 3 };
    expect(jcs(obj1)).toBe(jcs(obj2));
  });

  it('handles nested objects', () => {
    const obj = { 
      "@type": "WebSite", 
      "url": "https://github.com",
      "meta": { "b": 2, "a": 1 }
    };
    const canonical = jcs(obj);
    expect(canonical).toContain('"@type":"WebSite"');
    expect(canonical).toContain('"meta":{"a":1,"b":2}');
  });

  it('handles arrays', () => {
    const obj = { items: [3, 1, 2] };
    expect(jcs(obj)).toBe('{"items":[3,1,2]}');
  });

  it('handles null', () => {
    expect(jcs(null)).toBe('null');
    expect(jcs(undefined)).toBe('null');
  });

  it('handles booleans', () => {
    expect(jcs(true)).toBe('true');
    expect(jcs(false)).toBe('false');
  });

  it('handles numbers', () => {
    expect(jcs(42)).toBe('42');
    expect(jcs(3.14)).toBe('3.14');
    expect(jcs(0)).toBe('0');
  });

  it('handles strings with escaping', () => {
    expect(jcs("hello")).toBe('"hello"');
    expect(jcs("hello\nworld")).toContain('\\n');
  });

  it('handles schema.org JSON-LD objects', () => {
    const segment = {
      "@context": "https://schema.org",
      "@type": "Organization",
      "name": "AcmeCorp"
    };
    const canonical = jcs(segment);
    // Keys should be sorted
    expect(canonical.indexOf('"@context"')).toBeLessThan(canonical.indexOf('"@type"'));
    expect(canonical.indexOf('"@type"')).toBeLessThan(canonical.indexOf('"name"'));
  });
});

describe('Semantic Segment Validation', () => {
  it('accepts valid segments', () => {
    expect(() => validateSemanticSegment({
      "@type": "WebSite",
      "url": "https://github.com"
    })).not.toThrow();
  });

  it('rejects segments without @type', () => {
    expect(() => validateSemanticSegment({
      "url": "https://github.com"
    })).toThrow(/must have @type/);
  });

  it('rejects non-object segments', () => {
    expect(() => validateSemanticSegment("not an object" as any)).toThrow(/must be a JSON object/);
    expect(() => validateSemanticSegment(null as any)).toThrow(/must be a JSON object/);
    expect(() => validateSemanticSegment([1, 2, 3] as any)).toThrow(/must be a JSON object/);
  });
});

describe('Semantic to Index Conversion', () => {
  it('produces deterministic indexes', () => {
    const segment = { "@type": "WebSite", "url": "https://github.com" };
    const entropy = new Uint8Array(64).fill(1);
    
    const index1 = semanticToIndex(segment, entropy, true);
    const index2 = semanticToIndex(segment, entropy, true);
    
    expect(index1).toBe(index2);
  });

  it('produces different indexes for different segments', () => {
    const segment1 = { "@type": "WebSite", "url": "https://github.com" };
    const segment2 = { "@type": "WebSite", "url": "https://gitlab.com" };
    const entropy = new Uint8Array(64).fill(1);
    
    const index1 = semanticToIndex(segment1, entropy, true);
    const index2 = semanticToIndex(segment2, entropy, true);
    
    expect(index1).not.toBe(index2);
  });

  it('produces different indexes for different entropy', () => {
    const segment = { "@type": "WebSite", "url": "https://github.com" };
    const entropy1 = new Uint8Array(64).fill(1);
    const entropy2 = new Uint8Array(64).fill(2);
    
    const index1 = semanticToIndex(segment, entropy1, true);
    const index2 = semanticToIndex(segment, entropy2, true);
    
    expect(index1).not.toBe(index2);
  });

  it('sets hardened bit when requested', () => {
    const segment = { "@type": "WebSite", "url": "https://github.com" };
    const entropy = new Uint8Array(64).fill(1);
    
    const hardenedIndex = semanticToIndex(segment, entropy, true);
    const nonHardenedIndex = semanticToIndex(segment, entropy, false);
    
    // Hardened indexes have bit 31 set (>= 2^31)
    expect(hardenedIndex).toBeGreaterThanOrEqual(0x80000000);
    expect(nonHardenedIndex).toBeLessThan(0x80000000);
  });

  it('produces same index regardless of key order in segment', () => {
    const segment1 = { "@type": "WebSite", "url": "https://github.com", "name": "GitHub" };
    const segment2 = { "url": "https://github.com", "name": "GitHub", "@type": "WebSite" };
    const entropy = new Uint8Array(64).fill(1);
    
    const index1 = semanticToIndex(segment1, entropy, true);
    const index2 = semanticToIndex(segment2, entropy, true);
    
    expect(index1).toBe(index2);
  });
});

describe('Semantic Path Derivation', () => {
  const masterNode = deriveMasterNodeFromMnemonic(TEST_MNEMONIC);

  it('derives keys from a simple semantic path', () => {
    const semanticPath = [
      { "@type": "WebSite", "url": "https://github.com" }
    ];
    
    const result = deriveFromSemanticPath(masterNode, semanticPath);
    
    expect(result.derivationPath).toMatch(/^m\/83696968'\/67797668'\/\d+'/);
    expect(result.age_private_key).toMatch(/^AGE-SECRET-KEY-1[0-9A-Z]+$/);
    expect(result.age_public_key).toMatch(/^age1[0-9a-z]+$/);
    expect(result.raw_entropy).toMatch(/^[0-9a-f]{64}$/);
    expect(result.semanticPath).toEqual(semanticPath);
  });

  it('derives keys from a multi-segment path', () => {
    const semanticPath = [
      { "@type": "Organization", "name": "AcmeCorp" },
      { "@type": "SoftwareApplication", "name": "backup-system" },
      { "@type": "DigitalDocument", "name": "database.sql" }
    ];
    
    const result = deriveFromSemanticPath(masterNode, semanticPath);
    
    expect(result.derivationPath).toMatch(/^m\/83696968'\/67797668'\/\d+'\/\d+'\/\d+'/);
    expect(result.age_private_key).toMatch(/^AGE-SECRET-KEY-1[0-9A-Z]+$/);
    expect(result.age_public_key).toMatch(/^age1[0-9a-z]+$/);
  });

  it('produces deterministic results', () => {
    const semanticPath = [
      { "@type": "Organization", "name": "MyOrg" },
      { "@type": "DigitalDocument", "name": "file.txt" }
    ];
    
    const result1 = deriveFromSemanticPath(masterNode, semanticPath);
    const result2 = deriveFromSemanticPath(masterNode, semanticPath);
    
    expect(result1.derivationPath).toBe(result2.derivationPath);
    expect(result1.age_private_key).toBe(result2.age_private_key);
    expect(result1.age_public_key).toBe(result2.age_public_key);
  });

  it('produces different results for different paths', () => {
    const path1 = [{ "@type": "WebSite", "url": "https://a.com" }];
    const path2 = [{ "@type": "WebSite", "url": "https://b.com" }];
    
    const result1 = deriveFromSemanticPath(masterNode, path1);
    const result2 = deriveFromSemanticPath(masterNode, path2);
    
    expect(result1.age_private_key).not.toBe(result2.age_private_key);
    expect(result1.age_public_key).not.toBe(result2.age_public_key);
  });

  it('order matters - [A, B] != [B, A]', () => {
    const pathAB = [
      { "@type": "WebSite", "url": "https://a.com" },
      { "@type": "WebSite", "url": "https://b.com" }
    ];
    const pathBA = [
      { "@type": "WebSite", "url": "https://b.com" },
      { "@type": "WebSite", "url": "https://a.com" }
    ];
    
    const resultAB = deriveFromSemanticPath(masterNode, pathAB);
    const resultBA = deriveFromSemanticPath(masterNode, pathBA);
    
    expect(resultAB.age_private_key).not.toBe(resultBA.age_private_key);
  });

  it('rejects empty semantic paths', () => {
    expect(() => deriveFromSemanticPath(masterNode, [])).toThrow(/non-empty array/);
  });

  it('rejects invalid segments in path', () => {
    const invalidPath = [
      { "@type": "WebSite", "url": "https://github.com" },
      { "url": "no-type-field" } // Missing @type
    ];
    
    expect(() => deriveFromSemanticPath(masterNode, invalidPath as any)).toThrow(/Invalid segment/);
  });

  it('handles complex schema.org objects', () => {
    const semanticPath = [
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        "name": "AcmeCorp",
        "identifier": "acme-001"
      },
      {
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        "name": "backup-system",
        "applicationCategory": "Utilities",
        "operatingSystem": "Linux"
      },
      {
        "@context": "https://schema.org",
        "@type": "CreateAction",
        "name": "Age Key Derivation",
        "object": {
          "@type": "DigitalDocument",
          "name": "database.sql",
          "encodingFormat": "application/sql"
        }
      }
    ];
    
    const result = deriveFromSemanticPath(masterNode, semanticPath);
    
    expect(result.derivationPath).toMatch(/^m\/83696968'\/67797668'\/\d+'\/\d+'\/\d+'/);
    expect(result.age_private_key).toMatch(/^AGE-SECRET-KEY-1[0-9A-Z]+$/);
    expect(result.semanticPath).toEqual(semanticPath);
  });
});
