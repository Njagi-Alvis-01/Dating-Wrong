import { AsyncLocalStorage } from 'node:async_hooks';
import { db, firebaseProjectId, firestoreDbId } from './firebaseAdmin.ts';

export interface RequestAuthContext {
  uid?: string;
  email?: string;
  idToken?: string;
}

const requestAuthStorage = new AsyncLocalStorage<RequestAuthContext>();

export function runWithRequestAuth<T>(ctx: RequestAuthContext, fn: () => T): T {
  return requestAuthStorage.run(ctx, fn);
}

export function getRequestAuth(): RequestAuthContext | undefined {
  return requestAuthStorage.getStore();
}

const FIRESTORE_BASE = `https://firestore.googleapis.com/v1/projects/${firebaseProjectId}/databases/${firestoreDbId}/documents`;

export function isAdminSdkPermissionError(err: any): boolean {
  if (!err) return false;
  const code = err.code;
  const msg = String(err.message || '');
  return (
    code === 7 ||
    code === 16 ||
    msg.includes('PERMISSION_DENIED') ||
    msg.includes('UNAUTHENTICATED') ||
    msg.includes('Could not load the default credentials')
  );
}

export function isUnauthenticatedPermissionError(err: any): boolean {
  return isAdminSdkPermissionError(err) && !getRequestAuth()?.idToken;
}

function toFirestoreValue(val: any): any {
  if (val === null) return { nullValue: null };
  if (typeof val === 'boolean') return { booleanValue: val };
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) return { nullValue: null };
    return Number.isInteger(val) ? { integerValue: String(val) } : { doubleValue: val };
  }
  if (typeof val === 'string') return { stringValue: val };
  if (val instanceof Date) return { timestampValue: val.toISOString() };
  if (Array.isArray(val)) {
    return {
      arrayValue: {
        values: val.filter((item) => item !== undefined).map(toFirestoreValue),
      },
    };
  }
  if (typeof val === 'object') {
    const fields: Record<string, any> = {};
    for (const [k, v] of Object.entries(val)) {
      if (v !== undefined) {
        fields[k] = toFirestoreValue(v);
      }
    }
    return { mapValue: { fields } };
  }
  return { stringValue: String(val) };
}

function toFirestoreFields(data: Record<string, any>): Record<string, any> {
  const fields: Record<string, any> = {};
  for (const [k, v] of Object.entries(data)) {
    if (v !== undefined) {
      fields[k] = toFirestoreValue(v);
    }
  }
  return fields;
}

function fromFirestoreValue(val: any): any {
  if (!val || typeof val !== 'object') return null;
  if ('nullValue' in val) return null;
  if ('booleanValue' in val) return Boolean(val.booleanValue);
  if ('integerValue' in val) return Number(val.integerValue);
  if ('doubleValue' in val) return Number(val.doubleValue);
  if ('stringValue' in val) return String(val.stringValue);
  if ('timestampValue' in val) return String(val.timestampValue);
  if ('arrayValue' in val) {
    const vals = val.arrayValue?.values || [];
    return vals.map(fromFirestoreValue);
  }
  if ('mapValue' in val) {
    return fromFirestoreFields(val.mapValue?.fields || {});
  }
  return null;
}

function fromFirestoreFields(fields: Record<string, any> = {}): Record<string, any> {
  const obj: Record<string, any> = {};
  for (const [k, v] of Object.entries(fields)) {
    obj[k] = fromFirestoreValue(v);
  }
  return obj;
}

function docResourceName(col: string, docId: string): string {
  return `projects/${firebaseProjectId}/databases/${firestoreDbId}/documents/${col}/${docId}`;
}

function extractDocIdFromName(name: string): string {
  const parts = name.split('/');
  return parts[parts.length - 1] || '';
}

function encodeDocPath(col: string, docId: string): string {
  return `${FIRESTORE_BASE}/${encodeURIComponent(col)}/${encodeURIComponent(docId)}`;
}

async function restFetch(url: string, options: RequestInit, idToken?: string): Promise<Response> {
  const headers = new Headers(options.headers || {});
  if (idToken) {
    headers.set('Authorization', `Bearer ${idToken}`);
  }
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  return fetch(url, { ...options, headers });
}

function canUseRestFallback(col: string, isWrite: boolean): string | null | undefined {
  const ctx = getRequestAuth();
  if (ctx?.idToken) return ctx.idToken;
  if (!isWrite && col === 'config') return ''; // config is publicly readable
  return undefined;
}

export interface QueryFilter {
  field: string;
  op: '==' | '!=' | '<' | '<=' | '>' | '>=' | 'in' | 'array-contains';
  value: any;
}

export interface QueryOptions {
  orderBy?: { field: string; direction: 'asc' | 'desc' };
  limit?: number;
}

function mapOpToRest(op: QueryFilter['op']): string {
  switch (op) {
    case '==':
      return 'EQUAL';
    case '!=':
      return 'NOT_EQUAL';
    case '<':
      return 'LESS_THAN';
    case '<=':
      return 'LESS_THAN_OR_EQUAL';
    case '>':
      return 'GREATER_THAN';
    case '>=':
      return 'GREATER_THAN_OR_EQUAL';
    case 'in':
      return 'IN';
    case 'array-contains':
      return 'ARRAY_CONTAINS';
  }
}

export async function fsGetDoc<T = Record<string, any>>(
  col: string,
  docId: string
): Promise<{ exists: boolean; id: string; data: T | null }> {
  try {
    const snap = await db.collection(col).doc(docId).get();
    return {
      exists: snap.exists,
      id: snap.id,
      data: snap.exists ? (snap.data() as T) : null,
    };
  } catch (err: any) {
    if (!isAdminSdkPermissionError(err)) throw err;
    const token = canUseRestFallback(col, false);
    if (token === undefined) throw err;

    const resp = await restFetch(encodeDocPath(col, docId), { method: 'GET' }, token || undefined);
    if (resp.status === 404) {
      return { exists: false, id: docId, data: null };
    }
    if (!resp.ok) {
      const errBody = await resp.text();
      throw new Error(`Firestore REST GET failed (${resp.status}): ${errBody}`);
    }
    const json = await resp.json();
    return {
      exists: true,
      id: docId,
      data: fromFirestoreFields(json.fields || {}) as T,
    };
  }
}

export async function fsSetDoc(
  col: string,
  docId: string,
  data: Record<string, any>,
  options?: { merge?: boolean }
): Promise<void> {
  try {
    await db.collection(col).doc(docId).set(data, options ? { merge: Boolean(options.merge) } : undefined as any);
    return;
  } catch (err: any) {
    if (!isAdminSdkPermissionError(err)) throw err;
    const token = canUseRestFallback(col, true);
    if (token === undefined) throw err;

    const keys = Object.keys(data).filter((k) => data[k] !== undefined);
    const maskParams =
      options?.merge && keys.length > 0
        ? '?' + keys.map((k) => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join('&')
        : '';

    const resp = await restFetch(
      `${encodeDocPath(col, docId)}${maskParams}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ fields: toFirestoreFields(data) }),
      },
      token
    );
    if (!resp.ok) {
      const errBody = await resp.text();
      throw new Error(`Firestore REST SET failed (${resp.status}): ${errBody}`);
    }
  }
}

export async function fsUpdateDoc(
  col: string,
  docId: string,
  data: Record<string, any>
): Promise<void> {
  try {
    await db.collection(col).doc(docId).update(data);
    return;
  } catch (err: any) {
    if (!isAdminSdkPermissionError(err)) throw err;
    const token = canUseRestFallback(col, true);
    if (token === undefined) throw err;

    const keys = Object.keys(data).filter((k) => data[k] !== undefined);
    const params = [
      ...keys.map((k) => `updateMask.fieldPaths=${encodeURIComponent(k)}`),
      'currentDocument.exists=true',
    ].join('&');

    const resp = await restFetch(
      `${encodeDocPath(col, docId)}?${params}`,
      {
        method: 'PATCH',
        body: JSON.stringify({ fields: toFirestoreFields(data) }),
      },
      token
    );
    if (!resp.ok) {
      const errBody = await resp.text();
      throw new Error(`Firestore REST UPDATE failed (${resp.status}): ${errBody}`);
    }
  }
}

export async function fsDeleteDoc(col: string, docId: string): Promise<void> {
  try {
    await db.collection(col).doc(docId).delete();
    return;
  } catch (err: any) {
    if (!isAdminSdkPermissionError(err)) throw err;
    const token = canUseRestFallback(col, true);
    if (token === undefined) throw err;

    const resp = await restFetch(encodeDocPath(col, docId), { method: 'DELETE' }, token);
    if (!resp.ok && resp.status !== 404) {
      const errBody = await resp.text();
      throw new Error(`Firestore REST DELETE failed (${resp.status}): ${errBody}`);
    }
  }
}

export async function fsQuery<T = Record<string, any>>(
  col: string,
  filters: QueryFilter[] = [],
  options: QueryOptions = {}
): Promise<Array<{ id: string; data: T }>> {
  try {
    let q: FirebaseFirestore.Query = db.collection(col);
    for (const f of filters) {
      q = q.where(f.field, f.op, f.value);
    }
    if (options.orderBy) {
      q = q.orderBy(options.orderBy.field, options.orderBy.direction);
    }
    if (options.limit) {
      q = q.limit(options.limit);
    }
    const snap = await q.get();
    return snap.docs.map((d) => ({ id: d.id, data: d.data() as T }));
  } catch (err: any) {
    if (!isAdminSdkPermissionError(err)) throw err;
    const token = canUseRestFallback(col, false);
    if (token === undefined) throw err;

    const structuredQuery: any = {
      from: [{ collectionId: col }],
    };

    if (filters.length === 1) {
      const f = filters[0];
      structuredQuery.where = {
        fieldFilter: {
          field: { fieldPath: f.field },
          op: mapOpToRest(f.op),
          value: toFirestoreValue(f.value),
        },
      };
    } else if (filters.length > 1) {
      structuredQuery.where = {
        compositeFilter: {
          op: 'AND',
          filters: filters.map((f) => ({
            fieldFilter: {
              field: { fieldPath: f.field },
              op: mapOpToRest(f.op),
              value: toFirestoreValue(f.value),
            },
          })),
        },
      };
    }

    if (options.orderBy) {
      structuredQuery.orderBy = [
        {
          field: { fieldPath: options.orderBy.field },
          direction: options.orderBy.direction === 'desc' ? 'DESCENDING' : 'ASCENDING',
        },
      ];
    }

    if (options.limit) {
      structuredQuery.limit = options.limit;
    }

    const resp = await restFetch(
      `${FIRESTORE_BASE}:runQuery`,
      {
        method: 'POST',
        body: JSON.stringify({ structuredQuery }),
      },
      token || undefined
    );

    if (!resp.ok) {
      const errBody = await resp.text();
      throw new Error(`Firestore REST QUERY failed (${resp.status}): ${errBody}`);
    }

    const rows: any[] = await resp.json();
    const results: Array<{ id: string; data: T }> = [];
    for (const row of rows) {
      if (row.document) {
        results.push({
          id: extractDocIdFromName(row.document.name),
          data: fromFirestoreFields(row.document.fields || {}) as T,
        });
      }
    }
    return results;
  }
}

export interface BatchWriteOp {
  type: 'set' | 'update' | 'delete';
  col: string;
  docId: string;
  data?: Record<string, any>;
  merge?: boolean;
}

export async function fsBatchCommit(ops: BatchWriteOp[]): Promise<void> {
  if (ops.length === 0) return;

  try {
    for (let i = 0; i < ops.length; i += 400) {
      const chunk = ops.slice(i, i + 400);
      const batch = db.batch();
      for (const op of chunk) {
        const ref = db.collection(op.col).doc(op.docId);
        if (op.type === 'set') {
          batch.set(ref, op.data || {}, op.merge ? { merge: true } : (undefined as any));
        } else if (op.type === 'update') {
          batch.update(ref, op.data || {});
        } else if (op.type === 'delete') {
          batch.delete(ref);
        }
      }
      await batch.commit();
    }
    return;
  } catch (err: any) {
    if (!isAdminSdkPermissionError(err)) throw err;
    const ctx = getRequestAuth();
    if (!ctx?.idToken) throw err;

    for (let i = 0; i < ops.length; i += 400) {
      const chunk = ops.slice(i, i + 400);
      const writes = chunk.map((op) => buildRestWrite(op));
      const resp = await restFetch(
        `${FIRESTORE_BASE}:commit`,
        {
          method: 'POST',
          body: JSON.stringify({ writes }),
        },
        ctx.idToken
      );
      if (!resp.ok) {
        const errBody = await resp.text();
        throw new Error(`Firestore REST BATCH COMMIT failed (${resp.status}): ${errBody}`);
      }
    }
  }
}

function buildRestWrite(op: BatchWriteOp): any {
  const name = docResourceName(op.col, op.docId);
  if (op.type === 'delete') {
    return { delete: name };
  }
  const data = op.data || {};
  const keys = Object.keys(data).filter((k) => data[k] !== undefined);
  const write: any = {
    update: {
      name,
      fields: toFirestoreFields(data),
    },
  };
  if (op.type === 'update') {
    write.updateMask = { fieldPaths: keys };
    write.currentDocument = { exists: true };
  } else if (op.merge) {
    write.updateMask = { fieldPaths: keys };
  }
  return write;
}

export interface FsTransaction {
  getDoc<T = Record<string, any>>(col: string, docId: string): Promise<{ exists: boolean; id: string; data: T | null }>;
  setDoc(col: string, docId: string, data: Record<string, any>, options?: { merge?: boolean }): void;
  updateDoc(col: string, docId: string, data: Record<string, any>): void;
  deleteDoc(col: string, docId: string): void;
}

export async function fsRunTransaction<R>(fn: (tx: FsTransaction) => Promise<R>): Promise<R> {
  try {
    return await db.runTransaction(async (adminTx) => {
      const txWrapper: FsTransaction = {
        async getDoc<T>(col: string, docId: string) {
          const snap = await adminTx.get(db.collection(col).doc(docId));
          return {
            exists: snap.exists,
            id: snap.id,
            data: snap.exists ? (snap.data() as T) : null,
          };
        },
        setDoc(col, docId, data, options) {
          const ref = db.collection(col).doc(docId);
          if (options?.merge) {
            adminTx.set(ref, data, { merge: true });
          } else {
            adminTx.set(ref, data);
          }
        },
        updateDoc(col, docId, data) {
          adminTx.update(db.collection(col).doc(docId), data);
        },
        deleteDoc(col, docId) {
          adminTx.delete(db.collection(col).doc(docId));
        },
      };
      return await fn(txWrapper);
    });
  } catch (err: any) {
    if (!isAdminSdkPermissionError(err)) throw err;
    const ctx = getRequestAuth();
    if (!ctx?.idToken) throw err;

    // Begin Firestore REST Transaction
    const beginResp = await restFetch(
      `${FIRESTORE_BASE}:beginTransaction`,
      {
        method: 'POST',
        body: JSON.stringify({ options: { readWrite: {} } }),
      },
      ctx.idToken
    );
    if (!beginResp.ok) {
      const errBody = await beginResp.text();
      throw new Error(`Firestore REST beginTransaction failed (${beginResp.status}): ${errBody}`);
    }
    const { transaction } = await beginResp.json();
    const pendingOps: BatchWriteOp[] = [];

    const restTx: FsTransaction = {
      async getDoc<T>(col: string, docId: string) {
        const name = docResourceName(col, docId);
        const getResp = await restFetch(
          `${FIRESTORE_BASE}:batchGet`,
          {
            method: 'POST',
            body: JSON.stringify({ documents: [name], transaction }),
          },
          ctx.idToken
        );
        if (!getResp.ok) {
          const errBody = await getResp.text();
          throw new Error(`Firestore REST tx batchGet failed (${getResp.status}): ${errBody}`);
        }
        const rows: any[] = await getResp.json();
        const first = rows[0];
        if (!first || first.missing || !first.found) {
          return { exists: false, id: docId, data: null };
        }
        return {
          exists: true,
          id: docId,
          data: fromFirestoreFields(first.found.fields || {}) as T,
        };
      },
      setDoc(col, docId, data, options) {
        pendingOps.push({ type: 'set', col, docId, data, merge: options?.merge });
      },
      updateDoc(col, docId, data) {
        pendingOps.push({ type: 'update', col, docId, data });
      },
      deleteDoc(col, docId) {
        pendingOps.push({ type: 'delete', col, docId });
      },
    };

    try {
      const result = await fn(restTx);
      const writes = pendingOps.map((op) => buildRestWrite(op));
      const commitResp = await restFetch(
        `${FIRESTORE_BASE}:commit`,
        {
          method: 'POST',
          body: JSON.stringify({ transaction, writes }),
        },
        ctx.idToken
      );
      if (!commitResp.ok) {
        const errBody = await commitResp.text();
        throw new Error(`Firestore REST tx commit failed (${commitResp.status}): ${errBody}`);
      }
      return result;
    } catch (txErr) {
      // Best-effort rollback on error
      await restFetch(
        `${FIRESTORE_BASE}:rollback`,
        {
          method: 'POST',
          body: JSON.stringify({ transaction }),
        },
        ctx.idToken
      ).catch(() => {});
      throw txErr;
    }
  }
}
