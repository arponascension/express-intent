export interface RedisClientAdapter {
  readonly kind: string;
  get(key: string): Promise<string | null>;
  set(
    key: string,
    value: string,
    opts?: { readonly ttlMs?: number; readonly ifNotExists?: boolean },
  ): Promise<boolean>;
  del(key: string): Promise<number>;
  expire(key: string, ttlMs: number): Promise<boolean>;
  incr(key: string): Promise<number>;
  decr(key: string): Promise<number>;
  zadd(
    key: string,
    score: number,
    member: string,
    opts?: { readonly ttlMs?: number },
  ): Promise<number>;
  zremRangeByScore(key: string, min: number, max: number): Promise<number>;
  zcard(key: string): Promise<number>;
  zrangeByScoreWithScores(
    key: string,
    min: number,
    max: number,
    limit?: number,
  ): Promise<ReadonlyArray<{ readonly member: string; readonly score: number }>>;
  publish(channel: string, message: string): Promise<number>;
  subscribe(channel: string, handler: (message: string) => void): Promise<() => Promise<void>>;
  eval?(script: string, keys: ReadonlyArray<string>, args: ReadonlyArray<string>): Promise<unknown>;
  quit?(): Promise<void>;
}
