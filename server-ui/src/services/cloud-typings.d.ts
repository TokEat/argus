declare namespace API {
  interface CloudRecommendationItem {
    region: string;
    region_name?: string;
    instance_type: string;
    cpu: number;
    memory_gb: number;
    family: string;
    status: string;
    instance_price: number;
    spot_price: number;
    total_hourly: number;
    currency: string;
    price_unit: string;
    price_source: 'spot' | 'postpaid' | string;
  }

  interface CloudRecommendationResult {
    recommendations: CloudRecommendationItem[];
    cheapest?: CloudRecommendationItem | null;
    warnings?: string[];
    regions_scanned: number;
    regions_succeeded: number;
    regions_failed: number;
    price_requests: number;
  }
}
