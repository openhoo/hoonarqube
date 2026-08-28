try { work(); } catch (error) {
  log(error);
  throw error;
}
