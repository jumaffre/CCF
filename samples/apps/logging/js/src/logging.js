function get_id_from_request_query(request) {
  const elements = request.query.split("&");
  for (const kv of elements) {
    const [k, v] = kv.split("=");
    if (k == "id") {
      return ccf.strToBuf(v);
    }
  }
  throw new Error("Could not find 'id' in query");
}

function get_record(map, id) {
  const msg = map.get(id);
  if (msg === undefined) {
    return { body: { error: "No such key" } };
  }
  return { body: { msg: ccf.bufToStr(msg) } };
}

function delete_record(map, id) {
  if (!map.delete(id)) {
    return { body: { error: "No such key" } };
  }
  return { body: true };
}

export function get_private(request) {
  const id = get_id_from_request_query(request);
  return get_record(ccf.kv["records"], id);
}

export function get_historical(request) {
  return get_private(request);
}

export function get_historical_with_receipt(request) {
  const result = get_private(request);
  result.body.receipt = ccf.historicalState.receipt;
  return result;
}

export function get_public(request) {
  const id = get_id_from_request_query(request);
  return get_record(ccf.kv["public:records"], id);
}

export function post_private(request) {
  let params = request.body.json();
  ccf.kv["records"].set(
    ccf.strToBuf(params.id.toString()),
    ccf.strToBuf(params.msg)
  );
  return { body: true };
}

export function post_public(request) {
  let params = request.body.json();
  ccf.kv["public:records"].set(
    ccf.strToBuf(params.id.toString()),
    ccf.strToBuf(params.msg)
  );
  return { body: true };
}

export function delete_private(request) {
  const id = get_id_from_request_query(request);
  return delete_record(ccf.kv["records"], id);
}

export function delete_public(request) {
  const id = get_id_from_request_query(request);
  return delete_record(ccf.kv["public:records"], id);
}

export function clear_private(request) {
  ccf.kv["records"].clear();
  return { body: true };
}

export function clear_public(request) {
  ccf.kv["public:records"].clear();
  return { body: true };
}

export function count_private(request) {
  const count = ccf.kv["records"].size;
  return { body: count };
}

export function count_public(request) {
  const count = ccf.kv["public:records"].size;
  return { body: count };
}
