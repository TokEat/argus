import React, { useState } from 'react';
import { Resizable } from 'react-resizable';
import 'react-resizable/css/styles.css';
import { Table, Tooltip } from 'antd';
import type { TableProps } from 'antd';
import type { ColumnType } from 'antd/es/table';

const columnKey = (column: unknown, index: number) => String((column as { key?: React.Key }).key ?? index);
const ResizableHeader = ({ children, onResizeStop, ...headerProps }: React.ThHTMLAttributes<HTMLTableCellElement> & { children?: React.ReactNode; onResizeStop?: (width: number) => void }) => {
    const key = (headerProps as React.ThHTMLAttributes<HTMLTableCellElement> & { 'data-result-column'?: string })['data-result-column'];
    const width = Number((headerProps as React.ThHTMLAttributes<HTMLTableCellElement> & { width?: number }).width) || 240;
    if (!key || !onResizeStop) return <th {...headerProps}>{children}</th>;
    return <Resizable axis="x" width={width} height={1} minConstraints={[90, 1]} maxConstraints={[900, 1]}
        onResizeStop={(_event, handle) => onResizeStop(handle.size.width)}>
        <th {...headerProps} style={{ ...headerProps.style, width }}>{children}</th>
    </Resizable>;
};

/** 扫描结果统一表格：固定列支持拉伸，超宽内容横向滚动，不被单元格文字覆盖。 */
export default function ResultTable<RecordType extends object>(props: TableProps<RecordType>) {
    const { columns = [], ...rest } = props;
    const renderCellText = (value: React.ReactNode) => {
        if (typeof value === 'string' || typeof value === 'number') {
            const text = String(value);
            return <Tooltip title={text}><span className="result-cell-ellipsis">{text}</span></Tooltip>;
        }
        return value;
    };
    const [widths, setWidths] = useState<Record<string, number>>({});
    const resizableColumns = columns.map((column, index) => {
        const { onHeaderCell, ...restColumn } = column as ColumnType<RecordType>;
        const width = widths[columnKey(column, index)] ?? (typeof column.width === 'number' ? column.width : 180);
        const originalRender = restColumn.render;
        return {
            ...restColumn, render: (...args: Parameters<NonNullable<ColumnType<RecordType>['render']>>) =>
                originalRender ? renderCellText(originalRender(...args) as React.ReactNode) : undefined,
            width,
            onHeaderCell: (record: RecordType, rowIndex?: number) => ({
                ...onHeaderCell?.(record, rowIndex),
                width,
                'data-result-column': columnKey(column, index),
                onResizeStop: (value: number) => setWidths(current => ({ ...current, [columnKey(column, index)]: value })),
            }),
        };
    });
    const totalWidth = columns.reduce((sum: number, column, index) => sum + (widths[columnKey(column, index)] ?? (typeof column.width === 'number' ? column.width : 180)), 0);
    return (
        <Table<RecordType>
            {...rest}
            className={`result-resizable-table${props.className ? ` ${props.className}` : ''}`}
            columns={resizableColumns as unknown as typeof columns}
            components={{
                ...(props.components || {}),
                header: { cell: ResizableHeader, ...(props.components?.header || {}) },
                table: (tableProps: React.TableHTMLAttributes<HTMLTableElement>) => <table {...tableProps} style={{ ...tableProps.style, width: totalWidth, minWidth: totalWidth }} />,
            }}
            scroll={{ x: totalWidth }}
            tableLayout="fixed"
        />
    );
}
