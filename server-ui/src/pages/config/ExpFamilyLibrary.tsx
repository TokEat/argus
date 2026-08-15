import { useMemo, useState } from 'react';
import { BranchesOutlined } from '@ant-design/icons';
import { Button, Card, Empty, Input, Space, Tag, Typography } from 'antd';

const { Text, Title } = Typography;

interface ExpFamilyLibraryProps {
    exps: API.Exp[];
    canManage: boolean;
    onOpen: (expID: string) => void;
    onCreateBranch: (root: API.Exp) => void;
}

export const ExpFamilyLibrary = ({ exps, canManage, onOpen, onCreateBranch }: ExpFamilyLibraryProps) => {
    const [search, setSearch] = useState('');
    const [selectedProduct, setSelectedProduct] = useState('');
    const productFamilies = useMemo(() => {
        const grouped = new Map<string, API.Exp[]>();
        exps.filter((item) => !item.parent_exp_id).forEach((item) => {
            const product = item.product_name?.trim() || '未分类';
            grouped.set(product, [...(grouped.get(product) || []), item]);
        });
        return Array.from(grouped.entries()).sort(([left], [right]) => left.localeCompare(right, 'zh-CN'));
    }, [exps]);
    const visibleFamilies = useMemo(() => {
        const term = search.trim().toLocaleLowerCase();
        return productFamilies.flatMap(([product, roots]) => roots.flatMap((root) => {
            if (selectedProduct && product !== selectedProduct) return [];
            const variants = exps.filter((item) => item.parent_exp_id === root.id);
            const haystack = [product, root.name, root.description, ...variants.flatMap((item) => [item.name, item.variant_key || '', item.description])].join(' ').toLocaleLowerCase();
            return term && !haystack.includes(term) ? [] : [{ product, root, variants }];
        }));
    }, [exps, productFamilies, search, selectedProduct]);

    return <Card className="exp-library-card" styles={{ body: { padding: 0 } }}>
        <div className="exp-library-toolbar">
            <div>
                <Title level={4} style={{ margin: 0 }}>产品 EXP 库</Title>
                <Text type="secondary">按产品与漏洞组织；main.yak 统一选择拥有独立参数的利用分支。</Text>
            </div>
            <Input.Search aria-label="搜索产品、漏洞或利用方式" allowClear placeholder="搜索产品、CVE、EXP 或利用方式" value={search} onChange={(event) => setSearch(event.target.value)} style={{ maxWidth: 420 }} />
        </div>
        <div className="exp-library-layout">
            <aside className="exp-product-nav" aria-label="产品分类">
                <Text strong className="exp-product-nav-title">产品</Text>
                <Button aria-label="筛选全部产品" type={selectedProduct === '' ? 'primary' : 'text'} block className="exp-product-button" onClick={() => setSelectedProduct('')}><span>全部产品</span><Tag>{exps.filter((item) => !item.parent_exp_id).length}</Tag></Button>
                {productFamilies.map(([product, roots]) => <Button aria-label={`筛选产品 ${product}`} key={product} type={selectedProduct === product ? 'primary' : 'text'} block className="exp-product-button" onClick={() => setSelectedProduct(product)}><span>{product}</span><Tag>{roots.length}</Tag></Button>)}
            </aside>
            <main className="exp-family-list">
                {visibleFamilies.length === 0 ? <Empty description="没有匹配的产品、漏洞或利用方式" /> : visibleFamilies.map(({ product, root, variants }) => (
                    <Card key={root.id} size="small" className="exp-family-card" title={<Space wrap><Text strong>{root.name}</Text><Tag>{product}</Tag><Tag color={root.status === 'published' ? 'green' : 'default'}>{root.status}</Tag><Tag color="orange">{root.risk_level}</Tag></Space>} extra={<Space>{canManage && <Button size="small" aria-label={`在 ${root.name} 下新增利用分支`} icon={<BranchesOutlined />} onClick={() => onCreateBranch(root)}>新增利用分支</Button>}<Button size="small" type="primary" aria-label={`打开 ${root.name}`} onClick={() => onOpen(root.id)}>进入 Studio</Button></Space>}>
                        <Text type="secondary">main.yak · {variants.length} 个利用分支{root.active_revision ? ` · Active R${root.active_revision}` : ''}</Text>
                        <div className="exp-variant-grid">
                            {variants.length === 0 ? <button type="button" className="exp-variant-empty" onClick={() => canManage && onCreateBranch(root)}>尚无利用分支</button> : variants.map((variant) => (
                                <button type="button" key={variant.id} className="exp-variant-card" aria-label={`打开利用分支 ${variant.name}`} onClick={() => onOpen(variant.id)}>
                                    <Text strong>{variant.name}</Text>
                                    <Text type="secondary">{variant.variant_key}.yak · {variant.status}{variant.active_revision ? ` · R${variant.active_revision}` : ''}</Text>
                                </button>
                            ))}
                        </div>
                    </Card>
                ))}
            </main>
        </div>
    </Card>;
};
